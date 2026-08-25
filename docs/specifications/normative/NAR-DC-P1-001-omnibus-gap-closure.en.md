# NAR-DC-P1-001 — Omnibus Phase 1 Gap Assignment and Closure Record

Status: **PROPOSED / UNSIGNED / NOT YET NORMATIVE**  
Project: **DOM Contracts**  
Date: **2026-08-05**  
Scope: **Phase 1A cryptographic boundary and Phase 1B minimum Nonce Vault**

> This document has no normative effect until the operator reviews the exact
> bytes, signs this file with the established Minisign identity, and the
> signature is verified and recorded. Implementation work that depends on a
> decision introduced here must remain fail-closed before ratification.

## 1. Purpose and authority

This record consolidates every Phase 1 gap known at the time of writing. It
does four different things explicitly:

1. assigns byte-exact decisions that can be ratified by the operator;
2. assigns architecture decisions that remove unsafe or bypassable production
   APIs;
3. records engineering defects that must be corrected by code and tests rather
   than by a signature; and
4. records evidence, platform, audit, and publication gaps that a signature
   cannot manufacture.

The authority order after ratification is:

1. P1-ARCH-002;
2. this signed record, only for the decisions expressly assigned here;
3. previously signed Phase 1 ADRs, NARs, registries, and manifests where they do
   not conflict with P1-ARCH-002 or this record;
4. the DOM Scriptless Contracts Master Specification v1.0;
5. existing tests and implementation.

This record does not authorize Phase 2, real funds, mainnet, production,
consensus changes, existing DOM wire changes, DL2P, a release, or publication
of `dom-contracts`.

## 2. Evidence baseline

The following evidence was inspected before this draft was created:

| Evidence | Revision or location | Finding |
|---|---|---|
| DOM Core authoritative baseline | `769822562565f18ef55423dc992e7aa661206b4a` | Canonical verifier, BLAKE2b-256 tagged hash, scalar/point codecs, and 739-byte Bulletproof verifier exist. |
| Local integrated DOM candidate | local Phase 1 integration branch based on the ratified coordinator history | Adaptor, two-nonce, SCAD0, and vault-facing code exist, but a raw safe-Rust bypass remains. |
| DOM Wallet V3 authoritative baseline | `1868e61bc39eca223d794348d70e48668ad06708` | The only previously ratified production sealer is Wallet-owned and cannot be depended upon by the independent DOM Contracts application. |
| DOM Contracts local history | independent repository, local commits only | Public lifecycle store, monotonic transitions, tombstones, CAS, restore quarantine, and process-death tests exist; secret persistence is deliberately absent. |
| Master Specification | v1.0, revision R1 | Share PoK and collaborative Bulletproof concepts are specified, but several bytes are explicitly proposed rather than frozen. |
| P1-ARCH-002 | operator-ratified architecture update | DOM Wallet and DOM Contracts must not share seed, keys, keystore, database, nonces, shares, or simultaneously controlled outputs. |

Relevant authoritative implementation locations include:

- `crates/dom-crypto/src/hash.rs::blake2b_256_tagged`;
- `crates/dom-crypto/src/scriptless.rs`;
- `crates/dom-crypto/src/bulletproof_bp.rs`;
- `crates/dom-crypto/src/range_proof.rs::MAX_PROVABLE_VALUE`;
- `crates/dom-consensus/src/validation.rs` and the unchanged real kernel
  signature-verification path;
- upstream `grin_secp256k1zkp::Secp256k1::bullet_proof_multisig` and its pinned
  C FFI `secp256k1_bulletproof_rangeproof_prove`;
- `dom-wallet-v3/crates/dom-wallet-crypto/src/lib.rs::{seal,open,encode,decode}`
  as algorithm-profile evidence only, not as a Contracts dependency.

The fresh independent comparison executed against integrated DOM commit
`b059f5c4279b86671efc078b5988c580a2a4e4d8`, tree
`ee208b95021b4a53311454027bc21ea57453fb1c`, and exited `0` with
`COMPARISON_COMPLETE matched_fields=311`. The frozen independent-output file
SHA-256 was
`68f7d9e9b202b2c4380fe913f69ab15ed5205871cc82c84e3ee78eaaf5762206`.
This closes only the 311-field comparison for that exact tree; it does not
close the API, audit, fuzz, platform, or publication gaps.

## 3. Exhaustive known gap ledger

The status in this table describes what this record does. `ASSIGNED` means the
operator can make the decision normative by signing this exact file.
`ENGINEERING` and `EVIDENCE` remain open after signature until objectively
proved.

| ID | Class | Gap | Treatment in this record |
|---|---|---|---|
| DC-P1-G001 | Architecture | Public Scriptless nonce derivation and raw partial-signing types in `dom-crypto` permit a safe downstream crate to bypass `NonceVaultV1`. | **ASSIGNED** in §4: move Scriptless-specific secret workflow ownership behind private `dom-adaptor` internals; retain only generic authoritative arithmetic in `dom-crypto`. |
| DC-P1-G002 | Architecture | Cargo features unify across dependents, so a production `dangerous-test-only` feature cannot be treated as an access-control boundary. | **ASSIGNED** in §4: deterministic secret helpers are test-configuration code only and are absent from the publishable production dependency graph. |
| DC-P1-G003 | Normative crypto | Share proof-of-knowledge statement, challenge reduction, nonce policy, codec, and rejection policy are not byte-frozen. | **ASSIGNED** in §5. |
| DC-P1-G004 | Normative crypto | `BpStatementV1`, common-nonce commitment, round messages, aggregation, and finalization are not byte-frozen. | **ASSIGNED** in §6. |
| DC-P1-G005 | Backend integration | The DOM wrapper currently uses the complete prover path and does not expose the already pinned multiparty `tau_x/T1/T2` phases safely. | **ENGINEERING** under §6.9. No new proof system is authorized. |
| DC-P1-G006 | Normative storage | The independent Contracts process has no ratified root-key provisioning, KDF, AEAD, envelope, AAD, rotation, or backup profile. | **ASSIGNED** in §§7–8. |
| DC-P1-G007 | Architecture | Reusing the Wallet V3 sealer crate would create forbidden Wallet-to-Contracts identity and dependency coupling. | **ASSIGNED** in §7: clean-room Contracts profile using the same reviewed algorithms and dependency families, with distinct domains and keys. No Wallet source migration. |
| DC-P1-G008 | Storage security | Secret records must never be persisted as plaintext while the sealer is unavailable. | **ASSIGNED** fail-closed rule in §7; **ENGINEERING** after ratification. |
| DC-P1-G009 | Filesystem security | Path-based locking permits root/lock inode substitution and TOCTOU if every operation resolves from an ambient absolute path. | **ASSIGNED** capability-directory rule in §8; **ENGINEERING** implementation and adversarial tests remain open. |
| DC-P1-G010 | Crash recovery | A durable session claim without a record can remain after process death and must not be deleted or reused. | **ASSIGNED** burn-on-reconcile rule in §8; **ENGINEERING** implementation/test remains open. |
| DC-P1-G011 | Restore recovery | Interrupted restore previously accepted a caller-supplied backup path on resume, permitting backup substitution. | **ASSIGNED** immutable in-vault restore snapshot in §8; current corrective implementation and tests remain **ENGINEERING**. |
| DC-P1-G012 | Exact-byte safety | A raw partial may be computed before the store records a durable attempt, permitting recomputation after a crash before persistence. | **ASSIGNED** attempt-before-open rule in §8; **ENGINEERING** integrated signer/store implementation remains open. |
| DC-P1-G013 | Codec | `PublicCommitmentStored` must not decode a reveal artifact; unknown state/kind combinations must fail closed. | **ENGINEERING** correction and mutation tests; no new normative value is needed. |
| DC-P1-G013A | Persisted format | Session claims, attempts, immutable exposures, journal entries, restore manifests, and completion markers lack one closed canonical V1 registry. | **ASSIGNED** in §§8.6–8.10. |
| DC-P1-G013B | Journal integrity | Existing marker files are not a complete predecessor-linked append-only journal and do not prove that every earlier transition is present. | **ASSIGNED** in §8.8; **ENGINEERING/EVIDENCE** remains open. |
| DC-P1-G013C | Artifact history | The current lifecycle record overwrites commitment with reveal and reveal with partial, so retry addresses only the latest artifact. | **ASSIGNED** immutable exposure ledger in §8.7; **ENGINEERING** remains open. |
| DC-P1-G013D | Registry conformance | The independent store temporarily accepts any nonzero opaque purpose while the authoritative `PurposeV1` dependency is unpublished. | **ASSIGNED** fail-closed conformance rule in §8.10; publication/pin remains external. |
| DC-P1-G014 | Rollback model | A local filesystem alone cannot prove that the complete vault directory was not replaced by an older authentic snapshot after restart. | **LIMITATION** in §8. Full adversarial rollback resistance requires a monotonic external anchor in a later authorized mission; it is not falsely claimed here. |
| DC-P1-G015 | Dependency | The integrated `dom-adaptor` revision is local and not consumable by an immutable public Git revision. | **EXTERNAL/PUBLICATION**. The operator's controlled-publication addendum authorizes resolution only after all pre-push conditions pass. |
| DC-P1-G016 | License | The empty `dom-contracts` remote had no license file or explicit license decision. | **ASSIGNED** in §9: MIT, matching both official DOM workspaces, subject to retaining third-party notices. |
| DC-P1-G017 | G0 evidence | A real one-input/one-output/one-kernel transaction validation test passes, but the Master Specification's full two-wallet regtest/RPC/P2P/confirmation/restart/rescan/spend scenario has not run on the candidate. | **EVIDENCE**; signature cannot close it. |
| DC-P1-G018 | Independent evidence | A fresh byte-for-byte comparison against the integrated revision was required. | **CLOSED FOR COMMIT `b059f5c4…`**: command exited `0`, `matched_fields=311`; it must rerun if relevant bytes change. |
| DC-P1-G019 | Secret hygiene | Fresh compiler-visible zeroization, secret-copy, unwind, logging, and constant-time audit of the final integrated revision is absent. | **EVIDENCE/REVIEW**. |
| DC-P1-G020 | Fuzz/sanitizer | Current-HEAD persistent parser/store/Bulletproof fuzz campaigns and sanitizer evidence are incomplete. | **EVIDENCE**. |
| DC-P1-G021 | Property tests | At least 10,000 new adaptor closed-cycle cases must execute on the final revision; historical counts cannot be reused. | **EVIDENCE**. |
| DC-P1-G022 | Crash matrix | Every required child-process death point, including durable attempt, staging, fsync, rename, tombstone, commit, and simulated export, has not yet executed. | **ENGINEERING/EVIDENCE**. |
| DC-P1-G023 | Cross-platform | Linux is the current execution platform; Windows and macOS execution evidence is absent. | **EVIDENCE**. Prepared workflows are not execution. |
| DC-P1-G024 | OS keystore | No Keychain, DPAPI, libsecret, TPM, Secure Enclave, or equivalent backend exists in either official repository. | **DEFERRED**. Phase 1 uses a passphrase-wrapped Contracts master key; OS keystores may wrap the same master key only in a later versioned ADR. |
| DC-P1-G025 | Witness/watchtower | Witness and watchtower are explicitly outside DOM-CONTRACTS-P1-001. | **DEFERRED**, not silently implemented and not claimed by the Phase 1B minimum candidate. |
| DC-P1-G026 | Budgets | Production numerical budgets, windows, timeouts, retry limits, and retention values lack measurement-backed ratification. | **DEFERRED**. No defaults are introduced here. |
| DC-P1-G027 | External audit | No independent external security audit has approved the final code. | **EVIDENCE/PRODUCTION BLOCKER**. |
| DC-P1-G028 | Remote publication | The controlled-push addendum authorizes only the minimal approved DOM Core commits; it does not authorize publishing `dom-contracts`. | **OPERATIONAL** rule in §10. |
| DC-P1-G029 | History/secret scan | Full selected-history secret, local-path, dump, database, and fixture classification must pass before publication. | **EVIDENCE**. |
| DC-P1-G030 | Off-device backup | Local Git bundles are not off-device backups. | **OPERATIONAL**; remains `OFF_DEVICE_BACKUP = PENDING` until separately performed. |
| DC-P1-G031 | DOM Wallet isolation | Old experimental Wallet worktrees contain Scriptless work, while the authoritative Wallet must remain free of Contracts dependencies and state. | **ENGINEERING/EVIDENCE** only for isolation classification; this mission does not modify or migrate the Wallet. |
| DC-P1-G032 | Mainnet safety | No mainnet contract-funding path may exist before later gates, publication, audit, and explicit activation. | **ASSIGNED**: mainnet remains disabled and production unauthorized. |

No known gap may be removed from the ledger merely because this file is signed.
Only the rows marked `ASSIGNED` receive normative values. Every other row
requires its stated evidence or later authority.

## 4. Decision A — Non-bypassable safe-Rust ownership boundary

### 4.1 Enforcement scope

The production security claim is precise: the public safe API of
`dom-adaptor` must not expose a Scriptless-specific route that derives,
reveals, signs with, serializes, duplicates, or reuses a secret nonce outside
the approved vault lifecycle. It is not a claim that arbitrary malicious Rust
code cannot implement secp256k1 arithmetic from scratch.

### 4.2 Ownership

The following Scriptless-specific items move out of the public `dom-crypto`
API and become private implementation details of `dom-adaptor`:

- `ScriptlessNonceDerivationV1`;
- `ScriptlessSecretNoncePairV1`;
- Scriptless-specific raw nonce public-key derivation;
- Scriptless-specific raw bound-partial signing;
- conversion of a live pair into persistable record scalars;
- deterministic auxiliary-randomness injection.

`dom-crypto` remains the sole authoritative owner of generic, constant-time
secp256k1 scalar/point operations, canonical parsing, BLAKE2b-256 tagged hash,
wide reduction, challenge delegation, and final verification. Minimal generic
arithmetic may remain public because it is a general cryptographic boundary,
not an alternative Scriptless protocol API.

`dom-adaptor` must not depend directly on `k256`, Wallet, storage, network,
transport, or an application crate.

### 4.3 Production route

The only production high-level route is statically parameterized by a concrete
implementation of `NonceVaultV1`. The route performs, in order:

1. durable reservation;
2. durable computation-attempt marking before any secret record is opened;
3. private computation inside the adaptor engine;
4. transfer by value of a non-cloneable pending public artifact to the vault;
5. exact-byte persistence and irreversible state transition;
6. receipt of an opaque, one-shot export capability; and
7. exposure of exactly the persisted typed artifact.

No production function accepts caller-supplied raw nonce scalars, a raw permit,
a receipt Boolean, a persistence Boolean, or a skip flag.

### 4.4 Test boundary

Deterministic nonce injection is compiled only under `cfg(test)` inside the
owning crate or in a separate non-publishable evidence workspace. It is not a
normal Cargo feature of a publishable production crate because dependency
feature unification is not an access-control mechanism.

Compile-fail tests must prove that an ordinary downstream caller cannot import
the Scriptless secret pair, construct or decode a capability, call raw
Scriptless nonce derivation, call raw reveal/partial signing, or reuse an
export capability.

### 4.5 Rejected alternatives

- Cargo feature gating: rejected because features unify.
- A public marker trait: rejected because a caller can implement it.
- Runtime plugins or `Box<dyn NonceVaultV1>` in production: rejected.
- A new unsafe ABI or sealed unsafe trait: rejected.
- Reversing the dependency to `dom-adaptor -> Wallet`: rejected.
- Claiming that a public raw API is safe merely because documentation says not
  to call it: rejected.

## 5. Decision B — Canonical share proof of knowledge V1

### 5.1 Registry additions

The following case-sensitive ASCII tags are registered:

```text
DOM:scriptless-share-pop:v1
DOM:scriptless-share-pop-challenge:v1
```

They use the authoritative DOM tagged-hash function only:

```text
H_tag(tag, data) = BLAKE2b-256(u16_le(len(ASCII(tag))) || ASCII(tag) || data)
```

No SHA-256/BIP340 duplicated-tag construction, BLAKE2s, or truncated
BLAKE2b-512 is permitted.

### 5.2 Statement encoding

`SharePoPStatementV1` is exactly 202 bytes:

| Offset | Size | Field | Encoding and validation |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `DSPO` |
| 4 | 2 | version | `0x0001`, little-endian |
| 6 | 32 | chain_id | trusted local chain adapter; nonzero |
| 38 | 32 | session_id | nonzero and lifetime-unique |
| 70 | 32 | participant_id | canonical participant identifier; nonzero |
| 102 | 1 | role | `0x01 Initiator`, `0x02 Responder`; all others rejected |
| 103 | 2 | participant_index | little-endian; in roster range |
| 105 | 33 | share_point | canonical compressed SEC1, nonidentity |
| 138 | 32 | terms_hash | nonzero canonical terms digest |
| 170 | 32 | recovery_binding_hash | nonzero canonical recovery-policy digest |

The prover and verifier recompute:

```text
context_digest = H_tag("DOM:scriptless-share-pop:v1", statement_202)
```

### 5.3 Prover nonce

The PoK nonce `a` is a fresh, nonzero secp256k1 secret scalar generated by the
authoritative DOM OS-CSPRNG boundary. RNG failure is terminal and fail-closed.
The application cannot supply `a`. Test injection exists only under the test
boundary in §4.4. `a` is separate from adaptor, two-nonce, Bulletproof,
transport, and witness secrets and is zeroized after response construction.

### 5.4 Challenge hash-to-scalar

Let `R_i` be the statement share point and `A = aG`. For checked `counter_u32`
starting at zero, define:

```text
challenge_input =
    context_digest_32 ||
    R_i_compressed_33 ||
    A_compressed_33 ||
    counter_u32_le

d0 = H_tag("DOM:scriptless-share-pop-challenge:v1", 0x00 || challenge_input)
d1 = H_tag("DOM:scriptless-share-pop-challenge:v1", 0x01 || challenge_input)
wide = d0 || d1
c = dom_crypto::scalar_from_wide_be(wide)
```

If reduction returns zero, increment `counter_u32` with checked arithmetic and
repeat. Overflow is terminal. All digest and wide buffers are zeroized after
use. The authoritative constant-time wide-reduction boundary is mandatory.

### 5.5 Proof and verification

```text
z = a + c*r_i mod q
ShareProofV1 = A_compressed_33 || z_be32
```

The proof codec is exactly 65 bytes. `A` must be canonical and nonidentity.
`z` is a canonical big-endian scalar in `[0, q-1]`; zero is accepted because a
valid Schnorr response can be zero. Values greater than or equal to `q` are
rejected.

Verification accepts only when:

```text
zG == A + cR_i
```

The comparison uses the authoritative DOM point equality boundary. The proof
is rejected for statement mismatch, role/index mismatch, malformed points,
identity points, trailing bytes, noncanonical scalar, duplicate participant,
wrong terms/recovery binding, or any mutated byte.

### 5.6 Required evidence

Ratification freezes bytes but does not close the gate. Required evidence
includes independent vectors for every intermediate, positive and negative
proofs, all role/index mutations, deterministic test-only KATs, parser fuzz,
zeroization review, and verification against the authoritative DOM backend.

## 6. Decision C — Collaborative DOM Bulletproof V1

### 6.1 Backend and invariant

This decision does not introduce a proof system. It exposes the multiparty
phases already present in the exact pinned `grin_secp256k1zkp` backend used by
DOM through a minimal checked DOM FFI wrapper. The final proof remains exactly
739 bytes, uses `nbits = 64`, proves the existing pair
`(value, MAX_PROVABLE_VALUE - value)`, and is verified by the unchanged DOM
verifier. No Scriptless byte is added to L1.

`MAX_PROVABLE_VALUE` is the authoritative DOM value `(1u64 << 52) - 1`.

### 6.2 Registry additions

```text
DOM:scriptless-bp-statement:v1
DOM:scriptless-bp-no-recovery:v1
DOM:scriptless-bp-common-commit:v1
DOM:scriptless-bp-common-joint:v1
DOM:scriptless-bp-common-nonce:v1
DOM:scriptless-bp-round1-commit:v1
```

All H_tag uses follow §5.1. These tags are not aliases for any Wallet, DL2P,
recovery-capsule, adaptor-nonce, or witness domain.

### 6.3 Statement encoding

For participant count `n` in `2..=16`, `BpStatementV1` is exactly
`187 + 65*n` bytes:

| Order | Size | Field | Rule |
|---:|---:|---|---|
| 1 | 4 | magic | ASCII `DSBP` |
| 2 | 2 | version | `0x0001` little-endian |
| 3 | 32 | chain_id | trusted, nonzero |
| 4 | 32 | session_id | nonzero |
| 5 | 1 | participant_count | `2..=16` |
| 6 | `32*n` | participant_ids | strictly ascending bytewise; no duplicates |
| 7 | 8 | value_noms | little-endian; `<= MAX_PROVABLE_VALUE` |
| 8 | 8 | max_provable_value | little-endian; exactly `(1<<52)-1` |
| 9 | 33 | value_generator | exact canonical DOM `H_DOM` encoding |
| 10 | 1 | commitment_share_count | exactly equal to participant count |
| 11 | `33*n` | commitment_shares | same participant order; canonical, nonidentity |
| 12 | 33 | aggregate_commitment | exact sum of ordered shares |
| 13 | 32 | recovery_binding_hash | exact capsule/extra-commit digest, or sentinel below |
| 14 | 1 | proof_bits | exactly `64` |

When no recovery capsule is present:

```text
recovery_binding_hash =
    H_tag("DOM:scriptless-bp-no-recovery:v1", empty_string)
```

The statement hash is:

```text
statement_hash = H_tag("DOM:scriptless-bp-statement:v1", statement_bytes)
```

### 6.4 Common nonce commit and reveal

Each participant generates fresh `q_i[32]` with the OS CSPRNG and persists it
only in the approved encrypted short-lived secret record. Before any reveal:

```text
common_commit_i = H_tag(
    "DOM:scriptless-bp-common-commit:v1",
    statement_hash || participant_id_i || q_i
)
```

All commitments must be durably accepted before any `q_i` reveal. Reveals are
accepted only over the authenticated end-to-end participant channel and must
match their commitments byte for byte.

```text
joint_secret = H_tag(
    "DOM:scriptless-bp-common-joint:v1",
    statement_hash || participant_count_u8 ||
    ordered(participant_id_i || q_i)
)
```

The common nonce is produced by the same 64-byte wide reduction construction
as §5.4, substituting tag
`DOM:scriptless-bp-common-nonce:v1` and input
`statement_hash || joint_secret || counter_u32_le`. A zero result retries with
checked counter arithmetic. All `q_i`, joint-secret, digest, and wide buffers
are zeroized after finalization or abort.

Each participant also generates an independent nonzero `private_nonce_i` using
the authoritative OS-CSPRNG scalar boundary. It is never derived from the
common nonce or public statement.

### 6.5 Round 1

Each participant calls the pinned backend multiparty first phase with:

- values `[value_noms, MAX_PROVABLE_VALUE - value_noms]`;
- blinds `[r_i, -r_i]`;
- aggregate commitments `[C, C_complement]` in that order;
- `n_commits = 2`;
- canonical DOM value generator;
- `nbits = 64`;
- the common nonce and local private nonce;
- the exact recovery bytes represented by `recovery_binding_hash`;
- output `T1_i` and `T2_i`.

Before reveal, the participant sends only:

```text
round1_commit_i = H_tag(
    "DOM:scriptless-bp-round1-commit:v1",
    statement_hash || participant_id_i || T1_i_33 || T2_i_33
)
```

After every commitment is accepted, `BpRound1ShareV1` is revealed as exactly
138 bytes:

```text
ASCII "DBR1" [4]
version_u16_le = 1 [2]
statement_hash [32]
participant_id [32]
participant_index_u16_le [2]
T1_i_compressed [33]
T2_i_compressed [33]
```

Every point is canonical and nonidentity. The aggregate values are the
authoritative point sums in participant order:

```text
T1 = sum(T1_i)
T2 = sum(T2_i)
```

### 6.6 Round 2

Each participant calls the pinned backend second phase with the same immutable
statement, common/private nonces, local blind pair, and aggregate `T1/T2` and
obtains `tau_x_i`.

`BpRound2ShareV1` is exactly 104 bytes:

```text
ASCII "DBR2" [4]
version_u16_le = 1 [2]
statement_hash [32]
participant_id [32]
participant_index_u16_le [2]
tau_x_i_be32 [32]
```

`tau_x_i` is a canonical scalar in `[0, q-1]`. The aggregate is scalar addition
modulo `q` in the same participant order. Duplicate, missing, reordered,
noncanonical, or mismatched shares fail closed.

### 6.7 Finalization

Finalization calls only the pinned backend final phase with the exact immutable
statement, aggregate `T1`, aggregate `T2`, aggregate `tau_x`, and the required
local values/blind pair. Success requires:

- backend return code `1`;
- output length exactly 739 bytes;
- verification by the unchanged DOM Bulletproof verifier;
- exact agreement on aggregate commitment, recovery/extra-commit bytes, and
  all statement fields; and
- no differences in existing L1 fields outside the proof bytes.

Finalization failure permanently aborts the cryptographic session and burns all
associated nonces. It never retries with the same nonce material.

### 6.8 Secret ownership

`q_i`, `private_nonce_i`, local blinding shares, complement shares, and
intermediate scalar shares are non-Clone, non-Copy, non-Debug, non-Display,
non-Serde, zeroizing types. Round 1 and Round 2 operations consume one-shot
stage capabilities. No network byte reaches FFI before exact decoding,
canonical re-encoding, bounds checking, and statement binding.

### 6.9 Required engineering and evidence

The DOM wrapper must use the exact pinned backend API rather than recreating
Bulletproof arithmetic. Unsafe is confined to the existing reviewed FFI module.
Required tests include two through sixteen participants where supported,
single-versus-multi verifier equivalence, all value boundaries, malformed
points/scalars, round reordering/duplication/omission, altered extra-commit,
739-byte exactness, subprocess FFI fuzz, sanitizers, and final verification by
the real DOM verifier.

## 7. Decision D — Independent Contracts storage cryptography V1

### 7.1 Independence

DOM Contracts does not depend on `dom-wallet-v3`, reuse its seed, password
object, keystore, database, identity, envelope files, or KDF domain. It uses a
clean-room Contracts profile implemented in `dom-scriptless-crypto` and called
by `dom-scriptless-store`.

The profile reuses the reviewed algorithm family and versions already deployed
by Wallet V3:

- Argon2id version `0x13`;
- HKDF-SHA256;
- ChaCha20-Poly1305 with a 256-bit key and 96-bit nonce;
- OS CSPRNG with reported failure;
- zeroizing secret buffers.

This is algorithm/profile reuse, not source migration and not shared key
ownership.

### 7.2 Public identifiers

At Contracts wallet creation, the OS CSPRNG generates two independent nonzero
32-byte public identifiers:

- `contract_wallet_id_32` — stable identity of the independent Contracts
  wallet storage; and
- `vault_id_32` — identity of the initial Nonce Vault instance.

Neither identifier is derived from a seed, mnemonic, signing key, password,
KEK, transaction, address, or DOM Wallet identity. Collisions within the local
store fail closed. Restore creates a new `vault_id_32` and a new nonce epoch.

### 7.3 Master key and unlock KDF

The OS CSPRNG generates a nonzero 32-byte `vault_master_key`. It is never stored
plaintext. A user passphrase is UTF-8 bytes held in a zeroizing, non-cloneable
buffer. Empty passphrases and passphrases outside `8..=1024` bytes are rejected.

The unlock profile is fixed:

```text
Argon2id version = 0x13
memory = 65,536 KiB
iterations = 3
parallelism = 1
output = 32 bytes
salt = fresh OS-CSPRNG 32 bytes
```

Let `argon_output_32` be the result. The wrapping key is:

```text
KEK = HKDF-SHA256(
    salt = salt_32,
    IKM = argon_output_32,
    info = u16_le(len("DOM:contracts-vault-unlock-kek:v1")) ||
           ASCII("DOM:contracts-vault-unlock-kek:v1") ||
           contract_wallet_id_32 || vault_id_32,
    L = 32
)
```

Argon output, KEK, passphrase buffers, and plaintext master-key buffers are
zeroized on success and every error path. KDF parameters are not caller
selectable in V1. A header that advertises any other parameter fails closed;
there is no downgrade-to-test profile in production.

### 7.4 Master-key envelope

`VaultMasterKeyEnvelopeV1` is exactly 182 bytes:

| Offset | Size | Field | Required value |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `DOMCVMK1` |
| 8 | 2 | version | `1` little-endian |
| 10 | 1 | KDF ID | `1 = Argon2id-v0x13 + HKDF-SHA256` |
| 11 | 1 | AEAD ID | `1 = ChaCha20-Poly1305` |
| 12 | 32 | contract_wallet_id | nonzero |
| 44 | 32 | vault_id | nonzero and distinct from contract_wallet_id |
| 76 | 32 | Argon2 salt | fresh OS-CSPRNG bytes |
| 108 | 4 | memory KiB | `65536` little-endian |
| 112 | 4 | iterations | `3` little-endian |
| 116 | 4 | parallelism | `1` little-endian |
| 120 | 12 | AEAD nonce | fresh OS-CSPRNG bytes |
| 132 | 2 | ciphertext length | exactly `48` little-endian |
| 134 | 48 | ciphertext | encrypted 32-byte master key plus 16-byte tag |

AEAD associated data is:

```text
u16_le(len("DOM:contracts-vault-master-wrap:v1")) ||
ASCII("DOM:contracts-vault-master-wrap:v1") ||
envelope_bytes[0..134]
```

Unknown IDs, reserved alternatives, wrong fixed values, wrong length, trailing
bytes, authentication failure, zero identifiers, or RNG failure fail closed.

### 7.5 Per-object key derivation

The registered, case-sensitive HKDF labels are:

```text
DOM:contracts-vault-secret-record-key:v1
DOM:contracts-vault-tombstone-key:v1
DOM:contracts-vault-backup-key:v1
```

For each encrypted object, generate a fresh 16-byte
`encryption_instance_id` and a fresh 12-byte ChaCha20-Poly1305 nonce with the
OS CSPRNG. Derive:

```text
object_key = HKDF-SHA256(
    salt = vault_id_32,
    IKM = vault_master_key_32,
    info = u16_le(len(role_label)) || ASCII(role_label) ||
           object_header_bytes[0..208],
    L = 32
)
```

The role label is selected only by the closed `key_role` byte. Re-encryption
creates a new `encryption_instance_id` and nonce. Exact resend reuses the
already persisted ciphertext bytes; it never re-encrypts.

### 7.6 Object envelope

The fixed header of `VaultObjectEnvelopeV1` is exactly 224 bytes:

| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `DOMCVOB1` |
| 8 | 2 | version | `1` little-endian |
| 10 | 1 | AEAD ID | `1` |
| 11 | 1 | key role | `1 secret record`, `2 tombstone`, `3 backup` |
| 12 | 2 | schema version | caller's closed canonical schema, little-endian, nonzero |
| 14 | 32 | contract_wallet_id | exact local identity |
| 46 | 32 | vault_id | exact local vault identity |
| 78 | 8 | nonce_epoch | little-endian, nonzero |
| 86 | 32 | session_id | nonzero |
| 118 | 32 | participant_id | nonzero |
| 150 | 1 | purpose | canonical upstream registry byte; zero rejected |
| 151 | 1 | record kind | closed record-kind registry below; unknown rejected |
| 152 | 8 | revision | little-endian, nonzero and monotonic |
| 160 | 32 | bound_digest | nonzero and exact-context bound |
| 192 | 16 | encryption_instance_id | fresh OS-CSPRNG bytes |
| 208 | 12 | AEAD nonce | fresh OS-CSPRNG bytes |
| 220 | 4 | plaintext length | little-endian; bounded by record kind |

The ciphertext follows immediately and is exactly `plaintext_length + 16`
bytes. There are no trailing bytes. AEAD associated data is:

```text
u16_le(len("DOM:contracts-vault-envelope-aad:v1")) ||
ASCII("DOM:contracts-vault-envelope-aad:v1") ||
object_header_224
```

The plaintext is the already frozen canonical record codec, never JSON, Serde,
bincode, CBOR, or native struct layout. For nonce secret records the accepted
plaintext length is exactly the upstream canonical range and context-derived
length; a generic maximum cannot override that check.

The V1 record-kind registry is closed:

```text
0x01 NonceSecretRecordV1       key_role = 0x01, schema_version = 0x0001
0x02 TombstoneV1               key_role = 0x02, schema_version = 0x0001
0x03 BackupManifestV1          key_role = 0x03, schema_version = 0x0001
```

Every other byte is rejected. A known record kind with the wrong key role or
schema version is also rejected. `NonceSecretRecordV1` plaintext is restricted
to the previously frozen context-derived range `387..=882` bytes. Witness
authentication keys, transport keys, signing shares, seeds, and master keys
are not members of this registry.

### 7.7 API hygiene

Master keys, KEKs, object keys, plaintext records, passphrases, and opened
secret records are non-Clone, non-Copy, non-Debug, non-Display, non-Serde,
zeroizing types. They have no general raw accessor. The narrow cryptographic
boundary receives and returns owned zeroizing buffers. Errors and logs contain
no identifiers that allow a secret record to be reconstructed and no secret
bytes.

The production implementation rejects deterministic RNG, caller-selected KDF
parameters, caller-supplied AEAD nonces, unauthenticated headers, and key-role
fallback.

### 7.8 Backup and restore

Nonce secret records are never restored into an active authorization. A backup
may contain authenticated public lifecycle records and tombstones. Any
nonterminal or ambiguous imported slot becomes `Burned` in a fresh vault ID and
fresh nonce epoch. Secret-record ciphertext from an old backup is not opened to
resume signing and is not copied into the active namespace.

Password change rewraps the same master key using a fresh salt, fresh nonce,
and a new complete master-key envelope committed atomically. It does not
re-encrypt object records. Master-key rotation is a separate migration that
must atomically re-encrypt all live objects and is not authorized in this
Phase 1 mission.

OS-keystore wrapping may be added only as a new versioned wrapper around the
same master key. There is no silent fallback from a configured OS keystore to
a plaintext file or weaker KDF.

### 7.9 Required evidence

Ratification does not approve the sealer. Required evidence includes:

- KATs for KDF, HKDF info, envelope header, AAD, and ciphertext;
- mutation of every header, ID, length, role, parameter, nonce, and AAD byte;
- wrong-password and KDF-downgrade rejection;
- RNG-failure injection;
- no nonce/key-pair reuse under concurrency and crash;
- zeroization and secret-copy review;
- bounded parser fuzz and ASan/libFuzzer execution;
- process-death tests around staging write, file sync, rename, directory sync,
  envelope replacement, tombstone, and export;
- independent review and dependency/license inventory.

## 8. Decision E — Filesystem, attempt, crash, and restore rules

### 8.1 Capability-rooted I/O

After opening, every vault operation is relative to a pinned directory
capability, not repeatedly resolved from an ambient absolute path. The
implementation uses a reviewed safe capability-filesystem library or an
equivalent safe wrapper. Application code adds no unsafe block.

The lock file is created exactly once during initialization, opened without
`create` during normal operation, held for every state transition, and checked
against the pinned root. Active root, record, marker, session, staging, and
restore-snapshot objects reject symlinks and unexpected file types. Replacing
the pathname while a process holds the directory capability cannot redirect
the current process to a different tree.

This prevents active path substitution. It does not claim detection of a
complete authentic old-directory rollback across process restart; §3
DC-P1-G014 remains explicit.

### 8.2 Orphan session claims

A session claim is a lifetime tombstone. If recovery finds a valid session
claim but no corresponding record, it must never delete the claim or recreate
`Reserved`. Under the exclusive vault lock it materializes a `Burned` record
at the next checked revision, persists an irreversible marker, synchronizes
the relevant file and directories, and leaves the claim in place. Corrupt or
conflicting claims quarantine the vault.

### 8.3 Attempt-before-open

Before opening any secret record for commitment, reveal, partial signature,
or other irreversible public artifact, the vault durably records an attempt
bound to:

- nonce identity;
- session ID;
- participant ID;
- purpose;
- phase/artifact kind;
- bound digest;
- expected revision; and
- digest of the canonical operation input.

Only after file sync, directory sync, and committed attempt state may the
secret be opened. If the process dies after the attempt and before exact output
bytes are durably stored, recovery burns the slot. It never recomputes using
that nonce. If exact output bytes and the irreversible transition are durable,
recovery may issue a one-shot permit only for byte-identical resend.

### 8.4 Restore snapshot binding

`restore_from` validates the backup under its own lock, copies the exact
validated public lifecycle snapshot into an immutable target-vault restore
snapshot, synchronizes it, and only then creates `restore-pending`.

`resume_restore` accepts only the target vault root. It reads the pending epoch
and the immutable in-vault snapshot. It never accepts a caller-supplied backup
path. Snapshot substitution, duplicate sessions, changed epoch, changed
record, trailing object, symlink, or digest mismatch keeps the vault
quarantined.

### 8.5 Durability result set

At every process-death point, exactly one result is permitted:

1. no public material is exported and the ambiguous slot is permanently
   burned; or
2. the exact already persisted bytes are recoverable for a one-shot,
   byte-identical resend.

Recomputation, nonce reuse, revision regression, tombstone loss, session-ID
reuse, budget refund, or two permits is forbidden.

### 8.6 Canonical identity and session-claim record

All fields below are local storage bytes, never DOM consensus or L1 wire.
`NonceIdentityV1` is exactly 105 bytes:

```text
session_id_32 || participant_id_32 || purpose_u8 ||
bound_digest_32 || nonce_epoch_u64_le
```

`SessionClaimV1` is exactly 155 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII magic `DOMNVSC2` |
| 8 | 2 | version `1` little-endian |
| 10 | 105 | `NonceIdentityV1` |
| 115 | 8 | claim revision, exactly `1` |
| 123 | 32 | claim digest |

The claim digest is:

```text
H_tag(
  "DOM:contracts-vault-session-claim:v1",
  bytes[0..123]
)
```

The tag `DOM:contracts-vault-session-claim:v1` is registered. A claim is
created with create-no-clobber semantics and is never removed during the
lifetime of the Contracts wallet. A duplicate session ID with different
identity bytes is a permanent conflict and quarantines the vault.

### 8.7 Attempt and immutable exposure records

The registered tags are:

```text
DOM:contracts-vault-attempt:v1
DOM:contracts-vault-exposure:v1
```

`AttemptRecordV1` is exactly 193 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII magic `DOMNVAT1` |
| 8 | 2 | version `1` little-endian |
| 10 | 105 | `NonceIdentityV1` |
| 115 | 8 | expected lifecycle revision, nonzero |
| 123 | 2 | `SigningPhaseV1` little-endian |
| 125 | 1 | artifact kind: `1 Commitment`, `2 Reveal`, `3 PartialSignature` |
| 126 | 3 | reserved, all zero |
| 129 | 32 | canonical operation-input digest |
| 161 | 32 | attempt digest |

The attempt digest is `H_tag("DOM:contracts-vault-attempt:v1",
bytes[0..161])`. Unknown phase or artifact bytes, nonzero reserved bytes, wrong
digest, wrong revision, trailing bytes, or identity mismatch fail closed.

An `ExposureRecordV1` is exactly `233 + outbound_length` bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII magic `DOMNVEX1` |
| 8 | 2 | version `1` little-endian |
| 10 | 1 | state: `1 Persisted`, `2 Authorized`, `3 Spent` |
| 11 | 1 | artifact kind: `1 Commitment`, `2 Reveal`, `3 PartialSignature` |
| 12 | 105 | `NonceIdentityV1` |
| 117 | 8 | exposure sequence, nonzero and monotonic for this identity |
| 125 | 8 | lifecycle revision, nonzero |
| 133 | 32 | operation-input digest, equal to the attempt record |
| 165 | 32 | outbound digest |
| 197 | 4 | outbound length little-endian, `1..=4096` |
| 201 | variable | exact outbound bytes |
| `201+len` | 32 | exposure-record digest |

```text
outbound_digest = H_tag(
  "DOM:contracts-vault-exposure:v1",
  artifact_kind_u8 || outbound_length_u32_le || exact_outbound_bytes
)

exposure_record_digest = H_tag(
  "DOM:contracts-vault-exposure:v1",
  all_record_bytes_before_exposure_record_digest
)
```

The fixed-size expression is therefore `233 + outbound_length`. Each exposure
sequence is an immutable create-no-clobber object; state advancement creates a
new immutable version linked through the journal and never overwrites the
persisted exact bytes. A lifecycle summary may point to the latest exposure,
but it is not the authority for resend.

The transport-owned retry route names an opaque exposure identifier and an
expected kind/digest already present in trusted protocol state. It loads the
immutable authorized record and returns a one-shot permit for the stored bytes.
It never accepts replacement bytes and never invokes a signer or KDF.

### 8.8 Canonical append-only journal

The tag `DOM:contracts-vault-journal-entry:v1` is registered. A
`JournalEntryV1` is exactly `88 + payload_length` bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII magic `DOMNVJR1` |
| 8 | 2 | version `1` little-endian |
| 10 | 8 | global sequence, starting at `1`, checked increment |
| 18 | 32 | previous entry digest; all zero only for sequence `1` |
| 50 | 1 | entry kind |
| 51 | 1 | flags, exactly zero in V1 |
| 52 | 4 | payload length little-endian, `0..=16384` |
| 56 | variable | canonical entry-kind payload |
| `56+len` | 32 | entry digest |

Closed entry-kind registry:

```text
0x01 Reserve
0x02 ComputationAttempt
0x03 CommitmentPersisted
0x04 ExposureAuthorized
0x05 RevealPersisted
0x06 PartialConsumed
0x07 AbortConsumed
0x08 Burned
0x09 RestoreBegin
0x0a RestoreRecord
0x0b RestoreComplete
0x0c EpochAdvance
```

```text
entry_digest = H_tag(
  "DOM:contracts-vault-journal-entry:v1",
  all_entry_bytes_before_entry_digest
)
```

Every sequence from `1` through the head must exist exactly once. Missing,
duplicate, reordered, truncated, extended, conflicting, wrong-predecessor, or
unknown-kind entries quarantine the vault. Journal compaction may copy the
complete verified chain into a new generation with a signed/anchored checkpoint
in a later mission; V1 does not delete or renumber entries.

This local hash chain detects corruption and incomplete prefixes. It does not
detect replacement by a complete older authentic prefix without the later
monotonic anchor described by DC-P1-G014.

### 8.9 Restore transaction manifest

The registered tags are:

```text
DOM:contracts-vault-record-set:v1
DOM:contracts-vault-restore-manifest:v1
DOM:contracts-vault-restore-complete:v1
```

For a canonical record set, sort records by their complete
`NonceIdentityV1` bytes. Encode each item as
`u32_le(record_length) || canonical_record_bytes`. The record-set digest is
`H_tag("DOM:contracts-vault-record-set:v1", record_count_u32_le ||
concatenated_items)`.

`RestoreManifestV1` is exactly 262 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII magic `DOMNVRT1` |
| 8 | 2 | version `1` little-endian |
| 10 | 16 | random restore transaction ID |
| 26 | 32 | contract_wallet_id |
| 58 | 32 | target vault_id |
| 90 | 8 | target current epoch |
| 98 | 8 | target journal sequence |
| 106 | 32 | target journal head digest |
| 138 | 32 | source backup vault_id |
| 170 | 8 | source backup epoch |
| 178 | 8 | source backup journal sequence |
| 186 | 32 | source backup journal head digest |
| 218 | 8 | exact successor epoch |
| 226 | 4 | source record count |
| 230 | 32 | source canonical record-set digest |

The manifest digest is
`H_tag("DOM:contracts-vault-restore-manifest:v1", manifest_262)`. It is stored
beside the canonical snapshot records in a staging directory whose name is
derived from the random transaction ID. After every file and subdirectory is
synced, the directory is atomically renamed to the single reserved
`restore-pending` name and the target root is synced. Presence of that
directory is the quarantine marker and complete resume input; there is no
separate pending file race.

`RestoreCompleteV1` is exactly 98 bytes:

```text
ASCII "DOMNVRC1" [8] ||
version_u16_le = 1 [2] ||
restore_transaction_id_16 ||
manifest_digest_32 ||
successor_journal_head_digest_32 ||
completion_digest_8
```

`completion_digest_8` is the first eight bytes of
`H_tag("DOM:contracts-vault-restore-complete:v1", bytes[0..90])`; the full
32-byte digest is also committed as the payload of the `RestoreComplete`
journal entry. Truncation is used here only as a corruption sentinel inside a
record already protected by the full journal digest; it is not an
authentication tag.

An orphan staging directory is never treated as a restore. It remains
quarantined for operator recovery and cannot block a new transaction by being
silently overwritten. A completed snapshot is retained through the evidence
retention period; V1 defines no automatic deletion.

### 8.10 Versioning, migration, and purpose policy

All magics, versions, tags, integer encodings, lengths, and registries in
§§8.6–8.9 are closed. Unknown values and trailing bytes fail closed. No Serde,
bincode, JSON, CBOR, or native struct layout defines these bytes.

The current unpublished experimental `DOMNVLR1`, `DOMNVTM1`, `DOMNVRS1`, and
`DOMNVRE1` files are not production formats. Production opening never silently
migrates them. If they exist outside tests, the vault reports an unsupported
development format and remains quarantined. A separately reviewed offline
migration tool may be authorized later; it must burn every ambiguous slot.

Until the public authoritative `dom-adaptor` pin exists, the store may carry a
purpose byte only as opaque quarantined development metadata and cannot enable
a production signing route. After pinning, construction requires an exhaustive
conversion from canonical `PurposeV1`; unknown bytes fail closed and `Sponsor`
is codec-recognized but rejected by strict Phase 1 policy.

## 9. Decision F — Repository license

The `dom-contracts` source repository uses the MIT License with the applicable
2026 project copyright notice. This matches the license declared by both
official DOM workspaces. The repository must include the full MIT text and
retain all required third-party notices.

This decision does not assert that every transitive dependency is MIT. A
machine-readable dependency and license inventory must pass before public
release. Copyleft or unknown-license findings require explicit review and are
not silently accepted.

## 10. Decision G — Controlled DOM adaptor publication and dependency pin

The operator's controlled-publication addendum is incorporated as an
operational authority, not as evidence that the candidate is ready.

Publication may occur only after:

- this record and all other required normative inputs are validly signed and
  verified;
- the G1A raw bypass in §4 is removed;
- the selected DOM commits contain only Phase 1 DOM Core work;
- the selected history secret scan passes;
- relevant tests, vectors, comparison, fuzz, and review evidence pass;
- the push is a non-force fast-forward to an explicitly audited remote branch;
  and
- the coordinator independently verifies the executor's exact commit, tree,
  files, command, exit code, and remote result.

The `dom-contracts` dependency then uses the public official URL and the full
immutable published revision. No absolute path, `[patch]` override, sibling
worktree path, fictitious revision, or cached-only proof is permitted in
tracked production manifests.

The addendum does not authorize a `dom-contracts` push, a release, a package,
a tag, a merge, Phase 2, production, or mainnet.

## 11. Gaps that ratification cannot close

Signing this document does not change any of the following statuses:

- the G1A implementation remains not ready until §4 and the remaining code
  work are implemented and reviewed;
- the G1B candidate remains blocked until the §7 sealer and §8 lifecycle are
  implemented and all crash tests pass;
- the full two-wallet G0 scenario remains unexecuted unless its exact command
  and evidence run;
- the 311-field comparison is closed only for the exact commit/tree recorded
  in §2 and must rerun after relevant changes; the 10,000-case property test,
  fuzz, sanitizer, zeroization/constant-time review, and full crash matrix
  remain evidence requirements;
- Windows and macOS remain unexecuted until real runners execute them;
- whole-directory adversarial rollback resistance remains outside the local
  filesystem guarantee until a later monotonic-anchor mission;
- independent external audit remains absent;
- publication and dependency pin remain pending until the controlled-push
  procedure actually succeeds; and
- production and mainnet remain unauthorized.

## 12. Required implementation order after ratification

1. Verify the signature and hash of this exact file and import it without byte
   changes into the normative amendments directory.
2. Correct the `dom-crypto`/`dom-adaptor` ownership boundary and prove the
   production feature graph contains no raw Scriptless secret route.
3. Implement and independently vector-test Share PoK V1.
4. Add the minimal checked multiparty Bulletproof wrapper and permanent tests.
5. Finish public lifecycle crash/restore corrections independent of secret
   encryption.
6. Implement the Contracts sealer and envelope codecs exactly as §7.
7. Bind the adaptor one-shot signer to the Contracts vault with the
   attempt-before-open rule.
8. Run all focused and workspace tests, fresh independent comparison, property
   tests, crash matrix, fuzz, sanitizers, secret scan, and official-source
   integrity checks.
9. Only if the controlled-publication preflight is fully green, delegate the
   minimal DOM push to a separate executor and independently audit it.
10. Pin `dom-contracts` locally to the verified public revision and run a clean,
    cache-independent reproducibility build.

## 13. Ratification effect

If the operator signs this exact file and the signature verifies, the
normative and architectural gaps assigned in §§4–10 become frozen for Phase 1.
Implementation must follow them byte for byte or stop and request a new signed
erratum. No implementation result, test result, gate approval, publication,
or production authorization is created merely by the signature.

## 14. Operator ratification block

```text
Document: NAR-DC-P1-001-omnibus-gap-closure.en.md
Decision: RATIFIED AS WRITTEN
Scope: DOM Contracts Phase 1A and Phase 1B inputs only
Production authorization: NO
Mainnet authorization: NO
Phase 2 authorization: NO
DOM Contracts publication authorization: NO
Signature scheme: Minisign
Signature file: NAR-DC-P1-001-omnibus-gap-closure.en.md.minisig
```

The private signing key must never be provided to, opened by, hashed by, or
used by an implementation agent. Verification uses only the established public
key.
