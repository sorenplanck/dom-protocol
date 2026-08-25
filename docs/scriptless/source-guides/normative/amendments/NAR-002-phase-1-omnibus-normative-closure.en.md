# NAR-002 — Phase 1 Omnibus Normative Closure

Status: **FINAL CANDIDATE — EFFECTIVE ONLY AFTER VALID DETACHED RATIFICATION**
Date: 2026-08-04
Scope: Phase 1/G1a and Phase 3-SNV/G1b
Supplements: ratified NAR-001, ADR-SNV-001, and ADR-SNV-002
Ratification authority: DOM release signing key, Minisign key ID `74197A95CA309CF0`
Verification public key: `RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`

## 1. Authority, effect, and safety boundary

This record is the single closure document for every normative gap found after
ratification of NAR-001, ADR-SNV-001, ADR-SNV-002, and the KAT V2 input fixture.
It is not effective while unsigned. A valid detached Minisign signature over
the exact bytes of this file makes the assignments below normative for DOM
Scriptless Contracts V1.

This record:

- assigns missing G1a identifiers, template bytes, transcript rules, signer
  rejection rules, and pre-signature names;
- assigns the complete G1b witness-chain identity, revised wire framing,
  transition and exposure registries, journal, budget ledger, durability,
  restore, and transport rules;
- deliberately supersedes the affected ADR-SNV-001 request, receipt,
  idempotency, epoch-link, and recovery clauses listed in §1.1;
- does not modify DOM consensus, the existing transaction/kernel/block wire,
  persisted blocks, genesis, network magic, PoW, fork choice, or the unchanged
  DOM signature verifier;
- does not import any DL2P type, framing, state machine, receipt, nullifier,
  storage rule, or test vector;
- does not approve G1a or G1b. Ratification freezes inputs only. Every gate
  still requires executed implementation, independent-vector, fuzz,
  sanitizer, crash, isolation, and platform evidence.

### 1.1 Explicit supersession

After ratification, this record supersedes only these clauses of ADR-SNV-001:

1. §6 request body layout and sizes;
2. §6.1 registration and successor-epoch rules;
3. §8 receipt body layout and sizes;
4. §9 idempotency key and exact error-receipt fields;
5. §10 durability and restore details where this record is more specific;
6. §11 epoch-link preimage;
7. §15 HTTP response semantics and key-succession delivery.

All other ratified NAR-001, ADR-SNV-001, and ADR-SNV-002 clauses remain in
force. The unsigned draft named
`ADR-SNV-003-witness-transition-and-journal-registry.en.md` has no authority and
is replaced in full by this record.

## 2. Exhaustive gap ledger

| ID | Gap found | Closure in this record |
|---|---|---|
| G1A-01 | trusted chain-ID owner | §4 |
| G1A-02 | participant identity and roster mapping | §5 |
| G1A-03 | session-ID construction and contract kind | §6 |
| G1A-04 | complete canonical template bytes and owner | §7 |
| G1A-05 | initial transcript, accepted phase, ordering, retry | §8 |
| G1A-06 | zero challenge and degenerate result policy | §9 |
| G1A-07 | 65-byte algebraic versus 162-byte canonical pre-signature | §10 |
| G1A-08 | independent fixture participant identities | §11 |
| G1A-09 | nonce ID, outbound digest, permit, and exposure ordering | §§13–18 |
| G1B-01 | fresh-epoch rollback bypass | §§12 and 14 |
| G1B-02 | local Wallet, vault, key, counterparty, and request IDs | §13 |
| G1B-03 | revised request and receipt bytes | §14 |
| G1B-04 | transition, exposure, and lifecycle registries | §§15–16 |
| G1B-05 | journal and receipt-record bytes | §17 |
| G1B-06 | envelope, outbound, and budget-state digests | §18 |
| G1B-07 | receipt error fields and closed-epoch behavior | §19 |
| G1B-08 | exact durability and crash ambiguity behavior | §20 |
| G1B-09 | restore union/max and quarantine exit | §21 |
| G1B-10 | witness key pinning and succession delivery | §22 |
| G1B-11 | HTTP behavior and health endpoints | §23 |
| G1B-12 | witness durable concurrency and corruption behavior | §24 |
| G1B-13 | compaction and retention before measurement | §25 |
| G1B-14 | ordinary Wallet isolation | §26 |

The following are evidence gaps, not values that a signature can manufacture:
independent output comparison, constant-time review, compiler-visible
zeroization review, fuzz/sanitizer execution, crash-matrix execution, ordinary
Wallet isolation proof, Linux/Windows/macOS runs, and production budget
measurement. They remain open under §§27–29.

## 3. Closed additional domain-tag registry

All tags below use NAR-001 `H_tag`: authoritative DOM native BLAKE2b-256 over
`u16_le(tag_length) || tag_ascii || data`, with no key, salt, personalization,
alias, or runtime tag concatenation.

| Exact ASCII tag | Use |
|---|---|
| `DOM:scriptless-transcript-init:v1` | initial session transcript hash |
| `DOM:scriptless-vault-wallet-identity:v1` | stable local Wallet identity |
| `DOM:scriptless-vault-recovery-identity:v1` | seed-restorable secret identity intermediate |
| `DOM:scriptless-vault-chain:v1` | stable witness-visible vault-chain pseudonym |
| `DOM:scriptless-vault-budget-key:v1` | local signing-key budget ID |
| `DOM:scriptless-vault-counterparty:v1` | local counterparty budget bucket |
| `DOM:scriptless-vault-journal-entry:v1` | semantic journal digest |
| `DOM:scriptless-vault-receipt-record:v1` | local request/receipt record digest |
| `DOM:scriptless-vault-budget-policy:v1` | caller-supplied budget policy ID |
| `DOM:scriptless-vault-budget-state:v1` | complete post-transition charge ledger |
| `DOM:scriptless-vault-sealed-envelope:v1` | exact Wallet envelope digest |
| `DOM:scriptless-vault-outbound:v1` | stage-bound exact public output digest |
| `DOM:scriptless-vault-exposure-permit:v1` | canonical local permit digest |

The existing exact tags `DOM:scriptless-participant:v1`,
`DOM:scriptless-session-id:v1`, `DOM:scriptless-message:v1`,
`DOM:scriptless-transcript:v1`, `DOM:scriptless-template:v1`, and all tags
ratified by NAR-001 and ADR-SNV-001 retain their assigned meanings.

## 4. Trusted DOM chain-ID boundary

The exact Scriptless `chain_id_32` is the output of the existing authoritative
DOM function at the frozen official baseline:

```text
crates/dom-consensus/src/lib.rs::derive_chain_id
```

Its exact byte definition is:

```text
chain_id_32 = H_tag(
    "DOM:chain-id:v1",
    network_magic_u32_be || canonical_genesis_hash_32
)
```

Its code-authoritative input is the locally configured `network_magic` and the
locally authenticated canonical genesis identifier. Scriptless production code
must receive this value through a trusted chain adapter whose constructor is
not exposed to peer bytes or application-supplied arbitrary arrays.

The proposed Master Specification Appendix E.1 formula using
`DOM:scriptless-chain-id:v1` is revoked for V1 because it conflicts with the
deployed DOM chain-ID function. No second Scriptless chain ID exists. A peer,
fixture, restore package, or witness response cannot override the local value.
Mismatch fails before expensive scalar arithmetic or state mutation.

Signed cryptographic unit fixtures may use an exact authenticated synthetic
`chain_id_32` through a test-only constructor that is absent from release
feature resolution. That exception exists only to test byte binding and group
arithmetic; it cannot reach a production constructor, trusted chain adapter,
peer decoder, restore path, or witness client and is not evidence that the
synthetic value is a deployed chain ID.

## 5. Participant identity and roster mapping

The Master Specification §4.1 assignment is ratified exactly:

```text
participant_id_32 = H_tag(
    "DOM:scriptless-participant:v1",
    chain_id_32 || identity_public_key_33
)
```

Rules:

- the transport identity key is distinct from Wallet spending keys, excess
  signing shares, nonce keys, witness client keys, and witness server keys;
- the public key is canonical compressed nonidentity secp256k1 SEC1 and must
  re-encode byte-exactly;
- an all-zero participant ID is rejected;
- the protocol roster is strictly ascending by `participant_id_32`;
- the G1a signing roster inside NAR-001 `SessionContextV1` remains strictly
  ascending by `signing_public_key_33`;
- a frozen one-to-one mapping binds each participant ID, transport identity
  public key, signing public key, protocol-roster position, and G1a
  `participant_index`;
- duplicate IDs, duplicate identity keys, duplicate signing keys, missing
  mappings, or a mapping change after terms acceptance permanently abort the
  session;
- `participant_id_32` is used by the nonce commitment and authorization permit;
  it is not added to NAR-001 `canonical_context_v1` and does not change that
  signed layout.

## 6. Session ID and ContractKindV1

The complete Master Specification §4.1 construction is ratified:

```text
session_id_32 = H_tag(
    "DOM:scriptless-session-id:v1",
    version_u16_le
 || chain_id_32
 || initiator_nonce_32
 || initiator_participant_id_32
 || contract_kind_u16_le
)
```

`version_u16_le` is exactly V1 (`01 00`). `initiator_nonce_32` is fresh,
nonzero operating-system CSPRNG output generated before the first message. CSPRNG
failure is terminal. The initiator regenerates before any message if the
resulting session ID is all-zero or already exists in the local lifetime
session-ID set. A used session ID is retained as a tombstone and never reused
after abort, completion, restore, or compaction.

The closed V1 contract-kind registry is:

| u16 value | LE bytes | Exact name |
|---:|---|---|
| `0x0001` | `01 00` | `WitnessOrTimeout` |

`0x0000` and `0x0002..0xffff` are rejected. The cryptographic unit boundary may
accept explicit nonzero session IDs in signed test fixtures, but a production
session adapter must prove the construction above and its lifetime uniqueness.

## 7. Canonical transaction-template bytes

`complete_canonical_template_bytes` in NAR-001 is assigned to the following
Scriptless-only, signature-free projection of the existing DOM `Transaction`.
It does not replace or modify the DOM transaction wire.

```text
scriptless_transaction_template_v1 =
    "DOMSCTT1"[8]
 || schema_version_u16_le[2]
 || input_count_u32_le
 || inputs[input_count]
 || output_count_u32_le
 || outputs[output_count]
 || kernel_count_u32_le
 || kernels_without_signatures[kernel_count]
 || transaction_offset_32
```

Entry layouts:

```text
input = commitment_33

output = commitment_33
      || proof_length_u32_le
      || exact_proof_envelope[proof_length]

kernel_without_signature = features_u8
                         || fee_u64_le
                         || lock_height_u64_le
                         || excess_commitment_33
```

Rules:

- schema version is exactly `0x0001`;
- list counts, order, commitments, proof envelopes, limits, integer encodings,
  and offset are identical to `crates/dom-consensus/src/transaction.rs` and the
  existing `DomSerialize` rules at baseline
  `769822562565f18ef55423dc992e7aa661206b4a`;
- every kernel signature is omitted, not zero-filled, because it is the only
  field produced after template commitment;
- every other transaction byte is present exactly once and cannot be
  normalized after hashing;
- the owner is a narrow new `dom-consensus` adapter named
  `scriptless_transaction_template_bytes_v1`; `dom-adaptor` must call this
  boundary and must not duplicate the transaction projection;
- after final signatures are inserted, parsing the final transaction through
  the unchanged DOM codec and reprojecting it must produce byte-identical
  template bytes and the same NAR-001 template hash;
- every kernel message digest must also equal the existing
  `validate_kernel_signatures` construction over
  `features_u8 || fee_u64_le || lock_height_u64_le` under `TAG_KERNEL_MSG`;
- truncation, trailing bytes, excessive counts/proofs, invalid commitments,
  signature-bearing alternate templates, and reordering fail closed.

The adapter rejects a template unless every non-signature field is frozen.
Insertion of the exact final kernel signature bytes is the only permitted
post-hash mutation.

Authenticated cryptographic KAT boundaries may accept explicit synthetic
32-byte template and kernel-message digests solely to test binding and
arithmetic. They cannot be used as evidence for this template serializer or
kernel-message adapter. Production derives both through the authoritative
boundaries above.

## 8. Canonical session transcript

### 8.1 Initial hash

The initial accepted transcript hash is:

```text
initial_transcript_hash_32 = H_tag(
    "DOM:scriptless-transcript-init:v1",
    chain_id_32
 || session_id_32
 || contract_kind_u16_le
 || participant_count_u16_le
 || ordered_participants
)

ordered_participant = participant_id_32
                   || identity_public_key_33
                   || signing_public_key_33
                   || direction_u8
```

Participants are strictly ascending by participant ID. Count is 2 through 16.
`direction_u8` is the participant's role-stable NAR-001 `DirectionV1` byte.

### 8.2 Message digest and update

The Master Specification §8.1 fixed header and §8.2 digest are authoritative:

```text
session_message_digest_32 = H_tag(
    "DOM:scriptless-message:v1",
    message_bytes_from_magic_through_final_payload_byte
)

next_transcript_hash_32 = H_tag(
    "DOM:scriptless-transcript:v1",
    previous_transcript_hash_32
 || session_message_digest_32
 || direction_u8
 || accepted_phase_u16_le
)
```

The 65-byte transport-identity signature is excluded from
`session_message_digest_32`.
`session_message_digest_32` is not NAR-001 `message_digest`, which is named
unambiguously at implementation boundaries as `kernel_message_digest_32` and
is the exact digest accepted by the DOM kernel verifier. Only the resulting
`transcript_hash_32` enters NAR-001 `SessionContextV1`.
The fixed message header contains `DSC1`, V1, closed message type, zero flags,
the trusted chain ID, session ID, sender participant ID, sender sequence,
previous transcript hash, payload length, and the exact canonical payload.

For message types `SigNonceCommit`, `SigNonceReveal`, `PartialSignature`, and
`AdaptorPreSignature`, `accepted_phase_u16_le` is respectively NAR-001
`SigNonceCommit`, `SigNonceReveal`, `SigPartial`, and `SigAdapt`. `SigBinding`
is a deterministic local computation after all accepted reveals and is not a
wire-message phase. `SigExtract` is a local post-verification event and is not a
wire-message phase. Non-signing messages use the closed Master Specification
§9.1 base `Phase` value. The two registries are disjoint.

For a collective round, validated messages are applied sequentially in strict
ascending participant-ID order, regardless of arrival time. Each application
uses that sender's stable direction. This V1 rule supersedes the non-byte-exact
Master sentence suggesting an unspecified batch hash.

An exact duplicate logical key `(session_id, sender_id, sequence)` with exact
bytes returns the persisted result and does not update the transcript. Different
bytes under the same key are equivocation and permanently abort. A gap does not
advance the transcript. Terminal transcript hash is the hash after the final
accepted canonical message; local extraction does not mutate it.

Authenticated cryptographic KAT boundaries may accept an explicit synthetic
32-byte transcript hash solely to test binding and arithmetic. Such a value is
not evidence for the transcript initializer, DSC1 codec, ordering, or update
implementation. Production obtains it only from the validated session adapter.

## 9. Challenge and degenerate-result policy

The unchanged DOM verifier continues to parse a canonical challenge scalar in
`[0,n-1]`. This record does not change consensus or verifier behavior.

The Scriptless V1 signer is intentionally stricter:

- binding factor `b` remains NAR-001/ADR-0013 `[1,n-1]` direct big-endian,
  without reduction or retry;
- a DOM kernel challenge `e=0` or `e>=n` causes fail-closed session retirement
  and nonce burn without retry after any public material;
- zero partial scalar, zero aggregate `s_hat`, zero adapted `s`, identity or
  invalid `X_i`, `X`, `R_i1`, `R_i2`, effective `R_i`, aggregate `R`, or
  `R_hat` causes fail-closed retirement;
- no parity normalization, x-only rewrite, point negation, or scalar
  substitution is permitted;
- the unchanged verifier must accept the final 65-byte signature.

This is a stricter Scriptless construction policy, not a change to ordinary DOM
signature acceptance.

## 10. Pre-signature names and bytes

Two distinct objects have distinct names:

```text
core_adaptor_pre_signature_65 = R_hat_compressed_33 || s_hat_be32

adaptor_pre_signature_v1_162 = claim_template_hash_32
                                || adaptor_point_T_33
                                || R_hat_compressed_33
                                || s_hat_be32
                                || transcript_hash_32

final_dom_signature_65 = R_hat_compressed_33 || adapted_s_be32
```

The 65-byte core is the algebraic input to verification/adaptation. The 162-byte
object is the canonical Master Appendix E.6 protocol payload. Neither may be
called a final DOM signature. For ClaimAdaptor, `claim_template_hash_32` is
byte-identical to NAR-001 `SessionContextV1.template_hash_32`. Byte decoders
reject wrong length, invalid points/scalars, and trailing bytes. The external
session-bound validator, not the self-describing byte decoder, requires
`PurposeV1::ClaimAdaptor` and compares template hash, transcript hash, and T.

## 11. Complete independent-vector input freeze

### 11.1 Ratified input artifacts and scope

The ratified KDF input file in the coordinator repository is:

```text
test-vectors/scriptless/two-nonce/kat_inputs_v2.en.json
SHA-256 55642208968863a7b2c4773a82d9774f95f2a3b604b80a876d0bf031396b2a7d
```

The separately signed two-party input-only artifact in the independent evidence
worktree is:

```text
test-vectors/scriptless/two-nonce/kat_two_party_adaptor_inputs_v1.en.json
SHA-256 5e5063e819e7d64514039905c3c9fed0cb98c39f36c370fdb4c413751a08fac9
```

Its detached signature verifies with the key printed in this record. That file
defines the complete ClaimAdaptor input case and contains no expected outputs.
This record supplies participant identities and two non-adaptor cases. No
identity private scalar is published or required.

### 11.2 Common two-party inputs

| Field | Participant 0 | Participant 1 |
|---|---|---|
| G1a index | `0000` | `0100` |
| DirectionV1 | `01` Initiator | `02` Responder |
| signing share BE32 | `07` repeated 32 | `08` repeated 32 |
| signing public key | `02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f` | `03f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b` |
| aux randomness | `09` repeated 32 | `0a` repeated 32 |
| retry counter LE64 | `0000000000000000` | `0000000000000000` |
| transport identity key | `03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb` | `02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e` |
| participant ID | `c07141ea606c145a73e3fdbd20ed429025cb88b83cf214a1a8a36d620aa827b8` | `c8324097723644e5a773c4c6e1040818a397d9907c94dd02031dff9df1ed0f5d` |

Common context version is `0100`, chain ID is `aa` repeated 32, participant
count is `0200`, binding order is indexes `0000,0100`, and aggregate-excess
public keys are the two signing public keys in that order. Both identity points
are canonical; both participant IDs must be recomputed through §5. The IDs are
ascending and intentionally map to the signing-key indexes above.

Purpose-specific cases:

| Case | session ID | purpose | phase LE16 | template hash | kernel message digest | transcript hash | adaptor |
|---|---|---|---|---|---|---|---|
| `V1-Refund` | `01` repeated 32 | `01` | `0001` | `cc` repeated 32 | `dd` repeated 32 | `ee` repeated 32 | absent |
| `V1-ClaimAdaptor` | `42` repeated 32 | `02` | `0001` | `ab` repeated 32 | `bc` repeated 32 | `cd` repeated 32 | secret BE32 `00..05`; T `022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4` |
| `V1-Funding` | `03` repeated 32 | `03` | `0001` | `ac` repeated 32 | `bd` repeated 32 | `ce` repeated 32 | absent |

These synthetic chain/template/kernel/transcript values are permitted only by
the test-only exceptions in §§4, 7, and 8. They test cryptographic binding and
cannot prove the production adapters. ClaimAdaptor requires adaptation and
extraction outputs. Refund and Funding require complete two-party non-adaptor
aggregation and final real-verifier execution but have no adaptor outputs.

### 11.3 Exact nonce-commitment framing

For ClaimAdaptor the body offsets are:

| Offset | Field | Size |
|---:|---|---:|
| 0 | chain ID | 32 |
| 32 | session ID | 32 |
| 64 | participant ID | 32 |
| 96 | purpose | 1 |
| 97 | template hash | 32 |
| 129 | R1 | 33 |
| 162 | R2 | 33 |
| 195 | T | 33 |

The ClaimAdaptor body is 228 bytes. The tag is 30 ASCII bytes, so the complete
tagged input is `1e00 || ASCII("DOM:scriptless-nonce-commit:v1") || body`,
exactly 260 bytes. Refund and Funding append zero bytes for T: body length is
195 and complete tagged input length is 227. No presence byte, participant
index, direction, phase, message, transcript, count, identity sentinel, or
zero-filled T is appended.

### 11.4 Exact collective-binding framing for two participants

| Offset | Field | Size/value |
|---:|---|---|
| 0 | chain ID | 32 |
| 32 | session ID | 32 |
| 64 | purpose | 1 |
| 65 | template hash | 32 |
| 97 | signing-key count | 4, `02000000` |
| 101 | X0 then X1 | 66 |
| 167 | nonce-pair count | 4, `02000000` |
| 171 | R01, R02, R11, R12 | 132 |
| 303 | T for ClaimAdaptor | 33 |

ClaimAdaptor body length is 336. The tag is 32 ASCII bytes, so the complete
tagged input is `2000 || ASCII("DOM:scriptless-sig-nonce-bind:v1") || body`,
exactly 370 bytes. Refund and Funding omit T: body length is 303 and complete
tagged input length is 337. Participant IDs, commitment digests, kernel
message, direction, phase, transcript, and presence/sentinel bytes are not
appended. The binding digest maps directly as big-endian `[1,n-1]` without
reduction or retry.

ClaimAdaptor uses `R_hat = R + T`. Refund and Funding use `R_hat := R`, with no
point addition and no encoded identity, sentinel, or zero-filled pseudo-point.

### 11.5 Exact DOM challenge framing

```text
challenge_body_130 = R_hat_33
                  || aggregate_excess_X_33
                  || chain_id_32
                  || kernel_message_digest_32
```

Offsets are 0, 33, 66, and 98. The tag is 17 ASCII bytes, so the exact input to
BLAKE2b-256 is `1100 || ASCII("DOM:kernel-sig:v1") || challenge_body_130`, 149
bytes total. The kernel field is the already-computed 32-byte DOM kernel
message digest, not a DSC1 session-message digest or raw kernel struct.

### 11.6 Closed identity negative mutations

Each mutation starts from `V1-ClaimAdaptor`, replaces only the named complete
field, and expects rejection at the stated first boundary:

| ID | Exact mutation | First rejection |
|---|---|---|
| `ID-N1` | participant 0 identity prefix `03` becomes `04`, remaining 32 bytes unchanged | canonical SEC1 identity parser |
| `ID-N2` | participant 0 identity key becomes participant 1 identity key while its ID remains unchanged | participant-ID recomputation |
| `ID-N3` | participant 0 ID becomes `c17141ea606c145a73e3fdbd20ed429025cb88b83cf214a1a8a36d620aa827b8` | participant-ID recomputation |
| `ID-N4` | swap the two complete participant IDs only | ID/key mapping validation |
| `ID-N5` | set both participant IDs to participant 0 ID | duplicate roster validation |
| `ID-N6` | bind participant 0 ID to signing index 1 and participant 1 ID to signing index 0 | frozen one-to-one mapping validation |

For commitment field-mutation tests, XOR `0x01` into the first byte of exactly
one fixed field from §11.3 while retaining the original commitment digest. The
result rejects at the earliest applicable trusted-chain, bound-session,
participant-ID mapping, purpose/adaptor compatibility, canonical-point, or
commitment-mismatch boundary; the frozen output records that exact first
boundary. Binding mutation families independently change each count to
`01000000` or `03000000`, reorder one complete key or nonce pair, append
participant 0 ID as a forbidden final 32-byte field, omit T, or append the
ClaimAdaptor T to a non-adaptor purpose; all reject before partial verification.

### 11.7 Independence boundary

The independent generator commits complete expected intermediate bytes before
seeing production G1a. It first uses its independent library to establish the
compatible equations and outputs. Only after that commit may a separate DOM
Rust harness execute the unchanged real verifier against the frozen final
bytes. The independent generator is not required to import DOM Rust before its
pre-comparison commit.

## 12. Stable vault chain and epoch identity

Each canonical recovery seed has exactly one V1 Scriptless vault chain per DOM
chain. Its witness-visible pseudonym is derived inside the Wallet recovery-
secret boundary:

```text
recovery_identity_32 = H_tag(
    "DOM:scriptless-vault-recovery-identity:v1",
    chain_id_32 || genesis_id_32 || canonical_bip39_entropy_32
)

vault_chain_pseudonym_32 = H_tag(
    "DOM:scriptless-vault-chain:v1",
    recovery_identity_32
)
```

It must be nonzero and is stable across every epoch, backup, restore, process,
and device migration, including mnemonic-only restore that creates a fresh
Wallet UUID. It is not the Wallet UUID, local vault ID, user ID, contract ID,
session ID, address, transaction hash, spending public key, or a reversible
encoding of the mnemonic.

`canonical_bip39_entropy_32` is the exact 256-bit entropy already owned by
Wallet V3 `CanonicalWalletSeed`; it is never exposed through the Scriptless
application API. A narrow Wallet-owned method named
`CanonicalWalletSeed::scriptless_vault_chain_pseudonym_v1` computes both tagged
hashes internally. Canonical entropy and `recovery_identity_32` remain in
zeroizing guards on every success/error/unwind path and are never stored,
logged, serialized, sent to the witness, or returned. Only
`vault_chain_pseudonym_32` leaves that boundary.

A Wallet opened without the canonical recovery secret and without an
authenticated existing vault backup cannot initialize or reinitialize the
Scriptless subsystem; adaptor operations remain `RESTORE_QUARANTINED`. A
mnemonic-only restore can deterministically recover the same pseudonym, but it
cannot register a second genesis and cannot exit quarantine without the
receipt/journal reconciliation in §21.

The witness enforces exactly one genesis registration for each
`(chain_id_32, vault_chain_pseudonym_32)`. A new random epoch pseudonym or client
key cannot create a second genesis. This closes the fresh-epoch rollback bypass.

Initial epoch is exactly `1`. A successor is accepted only after a verified
closed receipt, uses `old_epoch + 1` with checked arithmetic, and carries the
exact old closed receipt-chain hash. Overflow is terminal. Epoch numbers and
vault-chain pseudonyms are never reused.

The superseding epoch-link commitment is:

```text
epoch_link_commitment_32 = H_tag(
    "DOM:scriptless-witness-epoch-link:v1",
    vault_chain_pseudonym_32
 || old_epoch_u64_le
 || old_epoch_pseudonym_32
 || old_closed_receipt_chain_hash_32
 || new_epoch_u64_le
 || new_epoch_pseudonym_32
 || new_client_key_id_8
)
```

For genesis, old epoch, old pseudonym, and old receipt hash are zero, and new
epoch is exactly one. For successors none of those old fields is zero.

## 13. Canonical local identifier assignments

### 13.1 Wallet and vault

The existing Wallet UUID is created and persisted by Wallet V3. Its 16 bytes
are encoded exactly as `uuid::Uuid::as_bytes()` and expanded as:

```text
wallet_identity_32 = H_tag(
    "DOM:scriptless-vault-wallet-identity:v1",
    wallet_id_uuid_raw_16 || chain_id_32 || genesis_id_32
)
```

An all-zero digest fails closed. The Wallet UUID, `chain_id`, and `genesis_id`
come from the authenticated Wallet state/chain adapter. `wallet_identity_32`
is local and never witness-visible.

`vault_id_32` is fresh nonzero OS-CSPRNG output at vault creation, stable in
authenticated backup/restore, and never witness-visible. It is distinct from
`vault_chain_pseudonym_32`.

### 13.2 Budget and operation identifiers

```text
key_id_32 = H_tag(
    "DOM:scriptless-vault-budget-key:v1",
    chain_id_32 || canonical_signing_public_key_33
)

counterparty_bucket_32 = H_tag(
    "DOM:scriptless-vault-counterparty:v1",
    chain_id_32 || counterparty_participant_id_32
)
```

Both digests must be nonzero. They are local and never appear on witness wire.
The counterparty is the exact protocol participant identity, not an address or
free-form label.

`reservation_nonce_id_32` follows ratified ADR-SNV-002. Every logical vault
operation has a fresh nonzero OS-CSPRNG `request_nonce_32`; byte-identical retry
reuses it and different bytes under it conflict. The witness request nonce is
also the operation idempotency key. No variable-length ID, UUID text, padded
UUID, index, transaction hash, or serialization hash substitutes for these
fields.

## 14. Revised witness RequestV1 and ReceiptV1

The ADR-SNV-001 15-byte common header and message-kind registry remain
unchanged. Every request kind `0x01..0x04` now has this exact 314-byte body:

| Offset in complete message | Field | Size |
|---:|---|---:|
| 15 | `epoch_pseudonym` | 32 |
| 47 | `vault_chain_pseudonym` | 32 |
| 79 | `chain_id` | 32 |
| 111 | `epoch` | 8 |
| 119 | `sequence` | 8 |
| 127 | `previous_receipt_hash` | 32 |
| 159 | `transition_commitment` | 32 |
| 191 | `request_nonce` | 32 |
| 223 | `client_key_id` | 8 |
| 231 | `client_public_key` | 33 |
| 264 | `client_signature` | 65 |

`body_length=314`; total request length is 329 bytes. The client-auth digest
covers `common_header_15 || request_body_without_signature_249` under the
existing ADR-SNV-001 tag.

Every receipt kind `0x81..0xe3` now has this exact 290-byte body:

| Offset in complete message | Field | Size |
|---:|---|---:|
| 15 | `request_kind` | 1 |
| 16 | `epoch_pseudonym` | 32 |
| 48 | `vault_chain_pseudonym` | 32 |
| 80 | `chain_id` | 32 |
| 112 | `epoch` | 8 |
| 120 | `sequence` | 8 |
| 128 | `receipt_link_field` | 32 |
| 160 | `transition_commitment` | 32 |
| 192 | `request_nonce` | 32 |
| 224 | `client_key_id` | 8 |
| 232 | `witness_key_id` | 8 |
| 240 | `witness_signature` | 65 |

`body_length=290`; total receipt length is 305 bytes. The receipt-signature
digest covers `common_header_15 || receipt_body_without_signature_225`. Receipt
chain hash covers the complete 305-byte wire receipt.

For `RegisteredReceipt`, `AdvancedReceipt`, and `ClosedReceipt`,
`receipt_link_field` is the predecessor applied-receipt chain hash and retains
the ADR-SNV-001 meaning `previous_receipt_hash`. For `HeadReceipt`,
`StaleReceipt`, and a known-chain `ConflictReceipt`, it is instead the complete
current applied head receipt-chain hash being reported. For
`UnknownEpochReceipt` it is zero. Non-applied receipts never become a
predecessor, so their own receipt-chain hash is not the reported head.

The idempotency key is
`(chain_id, vault_chain_pseudonym, epoch_pseudonym, request_nonce)`. Exact
retries return exact stored bytes. Old 297-byte requests and 273-byte receipts
are not V1 aliases and are rejected after this record is ratified.

## 15. Closed transition and exposure registries

### 15.1 WitnessTransitionKindV1

| Byte | Exact name |
|---:|---|
| `0x01` | `EpochRegistration` |
| `0x02` | `NonceReservation` |
| `0x03` | `ExposureAuthorization` |
| `0x04` | `NonceConsumption` |
| `0x05` | `NonceAbort` |
| `0x06` | `NonceBurn` |
| `0x07` | `EpochClosure` |

`0x00` and `0x08..0xff` are rejected. Query has no transition kind. Pending
storage actions have no normative kind. This registry is independent from the
ADR-SNV-002 sealed-record registry and from Rust enum declaration order.

### 15.2 ExposureKindV1

| Byte | Exact name | Exact canonical public bytes |
|---:|---|---|
| `0x01` | `NonceCommitment` | `SigNonceCommitV1`, 35 bytes |
| `0x02` | `NonceReveal` | `SigNonceRevealV1`, 69 bytes |
| `0x03` | `PartialSignature` | `PartialSignatureV1`, 67 bytes |

`0x00` and `0x04..0xff` are rejected. Aggregate pre-signature, adapted final
signature, and extracted secret are session-state artifacts, not exports of one
reserved participant nonce. They cannot be mislabeled with this registry.

## 16. Monotonic nonce lifecycle and stage ordering

The only normal path is:

```text
Reserved
 -> CommitmentAuthorized
 -> RevealAuthorized
 -> ConsumedPartialAuthorized
```

Terminal paths are:

```text
Reserved -> AbortedBeforePublicMaterial
CommitmentAuthorized -> ConsumedOnAbort
RevealAuthorized -> ConsumedOnAbort
any ambiguous nonterminal state -> Burned / RestoreQuarantined
```

Stage requirements:

1. reservation seals the one-shot secret pair, charges budget, persists the
   exact 35-byte commitment, and obtains the reservation witness receipt;
2. a distinct witnessed `ExposureAuthorization(NonceCommitment)` binds the
   exact commitment outbound digest; the commitment is returned only with the
   corresponding consumed `ExposurePermitV1(NonceCommitment)` after its exact
   bytes and receipt are durable;
3. reveal requires all expected commitments, byte-exact local commitment
   verification, exact 69-byte reveal persistence, and a separate witnessed
   `ExposureAuthorization(NonceReveal)`;
4. partial signing consumes `SecretNoncePair` by value into an unexportable
   prepared partial; failure retires the pair;
5. the exact 67-byte partial is persisted, witnessed as `NonceConsumption`, and
   the encrypted secret is destroyed with an irreversible tombstone before an
   `ExposurePermitV1(PartialSignature)` can release it;
6. no safe API returns any of the three public artifacts without the matching
   one-shot permit;
7. byte-identical retry reads persisted bytes and never recomputes them;
8. abort and burn are witnessed semantic transitions and are not reconciled
   until their applied receipts are durable;
9. abort never refunds budget; any uncertainty after commitment authorization
   burns the nonce.

## 17. Canonical semantic journal and receipt record

### 17.1 Journal entry

```text
journal_entry_v1 =
    "DOMSNVJE"[8]
 || schema_version_u16_le[2]
 || wallet_identity_32[32]
 || vault_id_32[32]
 || vault_chain_pseudonym_32[32]
 || epoch_u64_le[8]
 || semantic_revision_u64_le[8]
 || previous_local_journal_digest_32[32]
 || transition_kind_u8[1]
 || payload_length_u32_le[4]
 || transition_payload[payload_length]

local_journal_entry_digest_32 = H_tag(
    "DOM:scriptless-vault-journal-entry:v1",
    journal_entry_v1
)
```

The fixed prefix is exactly 159 bytes. Schema is one. Epoch is nonzero.
Semantic revision starts at zero for genesis registration and increments once
per witnessed semantic transition with checked arithmetic. It is distinct from
ADR-SNV-002 sealed-record revision and from pending/staging writes. Previous
digest is zero only at genesis. Receipt bytes are excluded to avoid a cycle.

Payloads:

| Transition | Exact payload and length |
|---|---|
| `EpochRegistration` | `epoch_pseudonym_32 || client_key_id_8 || prior_closed_receipt_hash_32 || epoch_link_commitment_32`, 104 |
| `NonceReservation` | `reservation_nonce_id_32 || key_id_32 || session_id_32 || counterparty_bucket_32 || purpose_u8 || encrypted_nonce_envelope_digest_32 || postcharge_budget_state_digest_32`, 193 |
| `ExposureAuthorization` | `reservation_nonce_id_32 || exposure_kind_u8 || outbound_digest_32 || postcharge_budget_state_digest_32`, 97 |
| `NonceConsumption` | `reservation_nonce_id_32 || exposure_kind_u8 || outbound_digest_32 || postcharge_budget_state_digest_32`, 97; exposure kind must be PartialSignature |
| `NonceAbort` | `reservation_nonce_id_32 || public_material_may_have_existed_u8 || postcharge_budget_state_digest_32`, 65 |
| `NonceBurn` | `reservation_nonce_id_32 || postcharge_budget_state_digest_32`, 64 |
| `EpochClosure` | `epoch_pseudonym_32 || last_applied_receipt_hash_32 || postcharge_budget_state_digest_32`, 96 |

The abort Boolean is exactly `0x00` or `0x01`; every other byte is rejected.
Payload length must equal the selected kind exactly. Unknown, duplicate,
reordered, truncated, extended, zero-ID, overflow, or predecessor-gap entries
fail closed.

Every registration request uses the generic transition commitment in §17.2.
The registration payload contains the independently recomputable §12
`epoch_link_commitment_32`; a mismatch fails before the generic commitment is
accepted. Genesis uses the exact zero-old-fields link rule in §12.

### 17.2 Transition commitment mapping

ADR-SNV-001 transition commitment retains its exact preimage, with the former
local names clarified as `transition_kind` and `transition_identifier`:

```text
H_tag(
    "DOM:scriptless-witness-transition:v1",
    chain_id_32
 || schema_version_u16_le
 || epoch_u64_le
 || sequence_u64_le
 || previous_receipt_hash_32
 || transition_kind_u8
 || semantic_revision_u64_le
 || transition_identifier_32
 || local_journal_entry_digest_32
)
```

Epoch registration/closure use epoch pseudonym as identifier. All nonce
transitions use reservation nonce ID. Registration sequence is zero; every
applied advance or closure is previous sequence plus one. Query and errors do
not increment sequence or semantic revision.

### 17.3 Receipt persistence record

```text
receipt_record_v1 =
    "DOMSNVRR"[8]
 || schema_version_u16_le[2]
 || semantic_revision_u64_le[8]
 || local_journal_entry_digest_32[32]
 || request_length_u32_le[4]
 || exact_request_bytes[request_length]
 || receipt_length_u32_le[4]
 || exact_receipt_bytes[receipt_length]
 || receipt_chain_hash_32[32]

receipt_record_digest_32 = H_tag(
    "DOM:scriptless-vault-receipt-record:v1",
    receipt_record_v1
)
```

Applied V1 request and receipt lengths are exactly 329 and 305. Stored hashes
must recompute. Error/query receipt records use the actual bounded canonical
message lengths but never become journal predecessors. A receipt record is
immutable and linked to exactly one semantic revision and request nonce.

## 18. Envelope, outbound, permit, and budget bytes

### 18.1 Exact envelope and outbound digests

```text
encrypted_nonce_envelope_digest_32 = H_tag(
    "DOM:scriptless-vault-sealed-envelope:v1",
    envelope_length_u32_le || exact_wallet_envelope_bytes
)

outbound_digest_32 = H_tag(
    "DOM:scriptless-vault-outbound:v1",
    exposure_kind_u8 || outbound_length_u32_le || exact_outbound_bytes
)
```

Lengths must match, be nonzero, fit `u32`, and satisfy the owning bounded codec.
Stage binding prevents the same bytes from being authorized under another
exposure kind.

### 18.2 ExposurePermitV1

The canonical local permit bytes are exactly 252 bytes:

```text
"DOMEXPV1"[8]
|| version_u16_le[2]
|| exposure_kind_u8[1]
|| permit_id_32[32]
|| reservation_nonce_id_32[32]
|| session_id_32[32]
|| participant_id_32[32]
|| purpose_u8[1]
|| template_hash_32[32]
|| outbound_digest_32[32]
|| epoch_u64_le[8]
|| semantic_revision_u64_le[8]
|| receipt_chain_hash_32[32]
```

`permit_id_32` is the exact witness request nonce for the authorizing
transition. The permit digest is `H_tag("DOM:scriptless-vault-exposure-permit:v1",
permit_bytes_252)`. The vault issues it only after exact outbound bytes,
journal, applied verified receipt, receipt record, and required tombstone are
durable. The signing/transport boundary exhaustively compares every bound field
and consumes the opaque permit by value. Permit types are not Clone, Copy,
Debug, Display, Serialize, or Deserialize. A persisted permit ID is permanently
spent even if delivery fails.

### 18.3 Budget policy and complete charge ledger

Numeric security limits remain caller-supplied. Their identity is:

```text
budget_policy_v1 =
    policy_version_u16_le
 || global_lifetime_limit_u64_le
 || counterparty_lifetime_limit_u64_le
 || concurrent_limit_u64_le
 || rolling_window_limit_u64_le
 || rolling_window_seconds_u64_le
 || maximum_forward_step_seconds_u64_le
 || durable_clock_kind_u8

budget_policy_id_32 = H_tag(
    "DOM:scriptless-vault-budget-policy:v1",
    budget_policy_v1
)
```

All six values are nonzero. The canonical policy body is 51 bytes. Version is
one. The only V1 durable clock kind is
`0x01 = UnixTimeSecondsHighWatermark`. OS monotonic clocks may control network
timeouts but do not replace the persisted cross-restart high watermark.

```text
budget_state_v1 =
    "DOMSNVBS"[8]
 || schema_version_u16_le[2]
 || budget_policy_id_32[32]
 || durable_time_high_watermark_u64_le[8]
 || charge_count_u32_le[4]
 || charges[charge_count]

charge_v1 = reservation_nonce_id_32
         || key_id_32
         || counterparty_bucket_32
         || charged_at_unix_seconds_u64_le
         || charge_state_u8

postcharge_budget_state_digest_32 = H_tag(
    "DOM:scriptless-vault-budget-state:v1",
    budget_state_v1
)
```

Each charge is 105 bytes and entries are strictly ascending by reservation
nonce ID. Charge states are closed: `0x01 Active`, `0x02 Consumed`,
`0x03 Aborted`, `0x04 Burned`; all other bytes are rejected. Every reservation
creates one lifetime charge. No transition deletes it. Global and counterparty
lifetime counts are counts of all matching charges. Concurrent count includes
Active charges. Rolling-window count includes charges whose persisted time is
within the caller-supplied window relative to the persisted high watermark.

Checked arithmetic is mandatory. Backward wall time causes quarantine and
never decreases the high watermark or refunds a charge. A forward step no
greater than the configured maximum is recorded. A larger forward step causes
quarantine and expires no rolling charge until reconciliation. Epoch rotation, restart, restore,
compaction, witness replacement, abort, consume, or burn never resets lifetime
counts.

The budget policy is immutable for one V1 vault chain. A policy change requires
a separately ratified migration that preserves the complete charge set and
cannot lower historical counts. Tests may create distinct disposable vaults
with distinct explicit policies; production cannot rewrite a live policy.

## 19. Exact receipt status semantics

For authenticated well-formed requests:

- an exact accepted-request retry returns the exact persisted applied receipt;
- `StaleReceipt` and `ConflictReceipt` for a known epoch copy the witness's
  current head sequence, current applied receipt-chain hash in
  `receipt_link_field`, and current head transition commitment;
- they copy request kind, chain ID, vault-chain pseudonym, epoch pseudonym,
  request nonce, and authenticated client key ID from the request;
- `UnknownEpochReceipt` copies those request identity fields but sets sequence,
  `receipt_link_field`, and transition commitment to zero;
- error receipts are signed but never advance or chain;
- a new advance against a closed epoch returns `StaleReceipt` with the closed
  head; a conflicting close returns `ConflictReceipt`; exact close retry
  returns the persisted `ClosedReceipt`;
- a request nonce reused with different complete bytes is Conflict;
- a second genesis or an invalid successor registration for a known stable
  vault chain returns `ConflictReceipt` carrying that stable chain's current
  head, even when the proposed fresh epoch pseudonym is unknown;
- remote-ahead data is acceptable locally only when every missing request is
  locally persisted and every applied signed receipt verifies byte-exactly.

## 20. Exact durability and crash ambiguity rules

For every new file-backed record, the minimum portable sequence is:

1. create a new staging file without replacing an existing target;
2. write all canonical bytes with checked complete-write handling;
3. synchronize file data and metadata;
4. atomically rename staging to the unique final name;
5. synchronize the parent directory;
6. only then publish the in-memory state transition.

An already-existing final name is accepted only after byte-exact verification
as an idempotent retry. An ambiguous I/O result is never treated as absence.
Recovery verifies both possible locations; disagreement quarantines and burns
the affected reservation.

Before any first export, the exact outbound bytes, semantic journal entry,
verified applied receipt, receipt record, receipt-chain hash, and spent permit
ID are durable. Before partial-signature export, the encrypted nonce secret is
irreversibly removed and a durable tombstone exists. File/data and directory
synchronization or the platform-equivalent durable primitive must complete.

No retry recomputes an outbound artifact. It returns exact persisted bytes or
fails closed. Panic, process death, power loss, cancellation, or network loss
between any two steps yields either exact recovery or burn/quarantine, never
nonce reuse or budget refund.

## 21. Restore and quarantine algorithm

Every restore begins in `RESTORE_QUARANTINED`. Reconciliation uses:

- set union by reservation nonce ID for tombstones and budget charges;
- maximum verified semantic revision only when every predecessor entry and
  digest exists;
- maximum verified witness sequence only when every signed receipt and exact
  persisted request exists;
- the highest durable time high watermark;
- the closed conservative charge merge: identical states remain unchanged;
  `Burned` dominates every state; any verified terminal state dominates
  `Active`; a conflict between `Consumed` and `Aborted` becomes `Burned`;
- permanent burn for any reservation with ambiguous public exposure,
  predecessor gap, missing exact output, missing request, or conflicting state;
- permanent preservation of every consumed/aborted/burned charge.

For the same reservation, a verified later terminal receipt and matching local
canonical record dominates an older Active copy. Without that proof, conflict
quarantines rather than selecting a convenient state. Remote ahead without the
matching local request remains quarantined. Local ahead retries only the exact
persisted request. Divergent valid receipts at one chain/epoch/sequence are
witness equivocation and require explicit operator resolution; no automatic
branch choice exists.

Exit from quarantine requires: stable vault-chain identity match, complete
local journal verification, complete applicable receipt-chain verification,
budget union completion, burn of every ambiguity, witness head agreement, and
durable recording of the reconciliation result. Ordinary Wallet operations do
not wait for this exit.

## 22. Witness key pinning and succession delivery

ADR-SNV-001 `WitnessKeySuccession` bytes and dual signatures remain unchanged.
Production pinning is out-of-band through the same authenticated software or
operator configuration channel that supplies the initial witness endpoint and
key. V1 defines no discovery endpoint and no trust-on-first-use.

The Wallet atomically persists the complete validated succession object, new
pin set, and activation boundary using §20 before accepting the new key. Both
signatures, chain ID, IDs, canonical key, activation boundary, and revoke flag
must verify. Earlier receipts retain the key needed for historical validation.
Loss of the old key without a valid succession object leaves adaptor operations
quarantined until a separately authenticated operator re-pin action; there is
no network-discovered or local-file fallback.

## 23. HTTP and service-health semantics

- endpoint is exactly `POST /v1/witness`;
- request and response media type is exactly `application/vnd.dom.snv.v1`;
- a well-formed authenticated request returns HTTP 200 with exactly one 305-byte
  signed receipt, including signed error receipts;
- malformed length/kind/body returns HTTP 400 with an empty body and no state
  change;
- failed client authentication returns HTTP 401 with an empty body and no state
  change;
- wrong media type returns HTTP 415 with an empty body and no state change;
- oversized input is rejected before allocation with HTTP 413 and empty body;
- redirects and content compression are disabled;
- `GET /healthz` returns HTTP 200, media type `text/plain`, body exactly
  `ok\n`;
- ready `GET /readyz` returns HTTP 200 and `ready\n`; not-ready returns HTTP
  503 and `not ready\n`;
- health bodies are at most 10 bytes and disclose no chain, vault, epoch, key,
  pseudonym, counter, receipt, or storage identifiers;
- positive connect/read/write timeouts and bounded retry policy are mandatory
  caller configuration; missing values are configuration failure.

## 24. Witness durable storage and concurrency

The witness commits accepted complete request bytes, complete signed receipt
bytes, chain head, and idempotency index atomically before responding. It
enforces unique keys for:

```text
(chain_id, vault_chain_pseudonym) genesis
(chain_id, vault_chain_pseudonym, epoch_pseudonym, sequence) applied transition
(chain_id, vault_chain_pseudonym, epoch_pseudonym, request_nonce) idempotency
```

Concurrent requests are serialized per stable vault chain. Exact-byte retry
returns stored bytes without a new signature. Conflicting uniqueness attempts
produce signed conflict evidence and no partial state. Storage corruption,
signature mismatch, missing predecessor, sequence gap, or ambiguous commit
makes the affected chain unavailable/fail-closed.

Witness private keys are externally provisioned and never generated on a
shared build host. The service persists no prohibited privacy field listed in
ADR-SNV-001. Logs are bounded and redact complete request/receipt bodies,
pseudonyms, keys, signatures, and transition commitments.

## 25. Retention and compaction

Production compaction is disabled until a measured, ratified compaction ADR
exists. V1 never deletes or rewrites tombstones, budget charges, canonical
journal entries, exact requests, applied receipts, receipt-chain evidence,
conflict/equivocation evidence, or key-succession objects required by any
supported restore horizon.

Retention and storage limits remain mandatory caller-supplied configuration.
If configured storage cannot preserve the required evidence, new adaptor
reservations fail closed before charging or nonce generation. Ordinary Wallet
operations remain available.

## 26. Ordinary Wallet isolation

The NonceVault, witness client, witness keys, budgets, receipt store, stable
vault-chain pseudonym, and anchor are reachable only through explicit
Scriptless/adaptor features and APIs. Ordinary create, open, restore, scan,
sync, plain send, submit, rebroadcast, and cancellation cannot initialize,
resolve, read, debit, or contact this subsystem and succeed with the witness
absent.

No production Cargo manifest may contain an absolute or sibling-worktree path.
Conformance may use an external local test harness, but that path cannot enter a
production manifest or lockfile.

## 27. Values deliberately not assigned

This record does not assign numeric production defaults for global lifetime
budget, counterparty lifetime budget, concurrent limit, rolling-window limit,
window duration, network timeout, retry count/schedule, retention, record-size
policy, maximum forward clock step, or compaction threshold. They remain nonzero caller-supplied values and
must be measured under the previously ratified measurement requirements.

A parser receives an explicit positive maximum from the owning canonical codec
or caller policy, rejects before allocation, and has no permissive fallback.
No security limit may be selected merely to make a test pass.

## 28. Mandatory conformance evidence

Ratification requires implementations to add and execute, at minimum:

- exact vectors and negative mutations for every byte layout in this record;
- independent G1a output generation committed before production comparison;
- byte-by-byte comparison of every G1a intermediate, not only final scalars;
- all eight SCAD0 vectors through the unchanged DOM verifier;
- 10,000 deterministic closed-cycle adaptor property cases;
- one-shot secret/permit type-state and zeroization/constant-time review;
- no direct `dom-adaptor -> k256` dependency;
- bounded persistent fuzz targets for every public G1a and witness parser;
- fault injection before/after every write, sync, rename, witness acceptance,
  receipt persist, permit, tombstone, and export boundary;
- every valid journal prefix, every record byte truncation, rollback to every
  prior prefix, duplicate/reorder/mutation/gap, remote-ahead/divergence,
  restore, epoch rotation, and concurrent reservation cases;
- proof of ordinary Wallet isolation by dependency graph, feature graph,
  call-graph review, compile-time checks, runtime witness-unavailable tests,
  source search, and frontend production build;
- proof that no secret or ADR-SNV-001-prohibited metadata appears in wire,
  logs, errors, panic text, corpus, or crash artifacts.

Self-generated vectors are not independent. A workflow file is not execution
evidence. A nonzero open-gate script result remains an open gate.

## 29. Gate status after ratification

If this record is validly signed, the normative gaps listed in §2 become
assigned. The following still remain open until actual evidence exists:

- G1a production implementation and authoritative adapters;
- independent full-vector outputs and byte comparison;
- G1a fuzz, sanitizer, constant-time, and zeroization evidence;
- G1b Wallet implementation, production witness client/service, and sealer
  conformance;
- G1b crash/fault matrix, rollback/restore, budget, and isolation evidence;
- Windows and macOS execution;
- publication/pinning and production-activation review.

Therefore signing this record alone cannot produce `PHASE 1 APPROVED`.

## 30. Ratification

Expected detached signature file:

```text
NAR-002-phase-1-omnibus-normative-closure.en.md.minisig
```

The signature must verify over the exact bytes of this file with the public key
printed in the header. No inline signature text modifies these bytes after
signing.
