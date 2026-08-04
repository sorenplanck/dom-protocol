# Gate G1a — pure cryptography

Status: **NOT APPROVED**. This checklist controls G1a only. Documentation,
implemented code, or implementation-generated tests do not by themselves close
a requirement. Independent frozen evidence and formal review remain required
where the gate specifies them.

- [ ] Adaptor signatures are specified and implemented only over authoritative DOM primitives.
- [ ] The two-nonce scheme with binding is specified and frozen.
- [ ] The canonical transcript, including binding, partials, and aggregation, is frozen byte-for-byte.
- [ ] Funding, ClaimAdaptor, and Refund execution purposes are closed and
      versioned; Sponsor is codec-recognized and policy-rejected.
- [ ] Domain separation between all three purposes is demonstrated.
- [ ] The canonical versioned hash-domain registry is frozen.
- [ ] The authoritative DOM hash is used exclusively through `blake2b_256_tagged`.
- [ ] Absence of a parallel BLAKE2b, challenge, parser, or verifier is independently confirmed.
- [ ] Constant-time operations cover all relevant secret material.
- [ ] Zeroization of nonces, shares, and secrets is demonstrated on every path.
- [ ] Secret types have no inappropriate `Debug`, cloning, or generic serialization.
- [ ] Eight SCAD0 vectors are frozen and reviewed byte-for-byte.
- [ ] Independent vectors for the two-nonce scheme are frozen.
- [ ] Adaptation and extraction are frozen in independent vectors.
- [ ] The final signature is verified by the real DOM verifier.
- [ ] Malformed and boundary scalars are rejected without ambiguity or panic.
- [ ] Malformed points, identity, and noncanonical encodings are rejected.
- [ ] Mutation of every critical field is covered by negative tests.
- [ ] Parser and G1a-operation fuzzing completes without panic.

Closing G1a does not close G1b or authorize real funds or production use.

## Implementation evidence versus gate evidence

| Area | Frozen input | Production implementation | Executed evidence | Independent validation | Gate state |
|---|---|---|---|---|---|
| DOM curve/scalar/point/hash profile | ADR-0009/0010 | reused from `dom-crypto` | backend KAVs and parser tests | partial existing KAV coverage | open pending review/audit |
| Purposes | ADR-0012/0018 | `PurposeV1` closed enum with Refund `01`, ClaimAdaptor `02`, Funding `03`, Sponsor `04`; strict policy rejects Sponsor | exhaustive 256-byte registry and codec/policy tests | normative table, no second implementation | input implemented/tested; gate open pending complete transcript and independent review |
| Direction and signing phase registries | ratified NAR-001; ADR-0019 | closed `DirectionV1` and `SigningPhaseV1` enums with explicit bytes | exhaustive positive and negative registry tests | signed KAT V2 inputs; independent outputs pending | input implemented/tested; gate open pending independent comparison |
| Canonical SessionContextV1 | ratified NAR-001 section 6; ADR-0019 | validating constructor, immutable private fields, exact encoder and bounded decoder | signed B1 input encoding, roundtrip, truncation and semantic-mutation tests; persistent fuzz target | signed input only; independent context bytes pending | implemented/tested; independent comparison open |
| Hash framing and commitment | ADR-0011/0012 | `nonce_commitment_hash_v1` | critical-field differential tests | Python-frozen tagged vectors cover backend framing | open pending complete transcript |
| Collective binding | ADR-0013 | `binding_factor_v1`, `BindingFactorV1` | exact frozen binding digest and grammar/order negatives | hash byte vector is independent; full scheme is not | open |
| Bound partial verification | ADR-0013/0017 | `PartialSignatureV1::verify_bound` and `dom_crypto::scriptless_verify_bound_partial` | authoritative DOM challenge test | independent aggregation vectors absent | open |
| Adaptor verify/adapt/extract | EM/RC, ADR-0014/0017 | `AdaptorPreSignatureV1` and `dom-crypto::scriptless` | all eight SCAD0 records and negative mutations | SCAD0 provenance remains correlated | open |
| Real final verifier | ADR-0014 | unchanged `schnorr_verify`; test-only consensus wrapper | all eight final kernels pass `validate_kernel_signatures` | consensus path is authoritative | implemented/tested; gate remains open with adaptor row |
| Secret handling | ADR-0009/0017 | opaque non-Clone/non-Debug `AdaptorSecret` and `ScriptlessSecretScalar`, `ZeroizeOnDrop` | compile-time API shape and behavior tests | dedicated audit absent | open |
| Parsers | ADR-0010/0011 | exact fixed-width fail-closed parsers and persistent libFuzzer targets | bounded panic/malformed/mutation tests; short Linux ASan campaigns | no independent parser review; canonical context parser blocked | open |
| Wide scalar reduction | mission decision; ADR-0018 | `dom_crypto::scalar_from_wide_be` delegates to constant-time `k256::Scalar::Reduce<U512>` inside the authoritative owner | zero, one, `n`, `n+1`, and high-bit tests | dedicated audit absent | implemented/tested; gate remains open with KDF row |
| Closed-cycle property | adaptor equations; ADR-0017 | existing authoritative boundary | 10,000 deterministic adapt/extract cycles; every final signature passed the real DOM verifier and every extraction passed `tG=T` | implementation-generated, not independent | implemented/tested; independent validation open |
| Secret two-nonce derivation | ratified NAR-001 section 7; ADR-0019 | OS-CSPRNG derivation, exact three tags, checked pre-export retry, authoritative wide reduction, RAII zeroization | deterministic KDF separation tests and production compile checks | signed KAT inputs only; independent intermediate outputs pending | implemented; gate open pending byte comparison and audit |
| One-shot partial signing | ratified NAR-001 sections 7.4 and 8; ADR-0019 | opaque pre-authorization pair, exact durable permit binding, authorized public export, consuming partial sign, bound verification and aggregation | two-participant closed workflow through unchanged DOM verifier | independent aggregate vector and G1b conformance pending | implemented; gate open |
| Authoritative chain/template adapters | ratified NAR-002 sections 4 and 7; ADR-0020 | trusted chain wrapper; `DOMSCTT1` projection; unchanged kernel-message adapter | chain derivation and signature-only template-invariance tests | independent template bytes pending | implemented/tested; gate open pending comparison |
| Participant/session/transcript mapping | ratified NAR-002 sections 5, 6, and 8; ADR-0020 | participant IDs, protocol roster, signing-index mapping, session ID, transcript init/update | ordering, closed registry, and domain-separation tests | independent intermediate outputs pending | implemented/tested; gate open |
| Exposure permit boundary | ratified NAR-002 sections 15, 16, and 18.2; ADR-0020 | closed exposure kinds; validation-only record parser; exact 252-byte permit; distinct crate-sealed one-shot commitment/reveal/partial authorization | exact parser, truncation, unknown-kind, premature/repeated/wrong-kind/mismatch tests; persistent fuzz target | G1b durable witness-backed issuance/conformance pending | fail-closed boundary implemented; gate open |
| Nonce derivation API safety | ratified NAR-001 section 7 and NAR-002 section 16; ADR-0019/0020 | OS-owned auxiliary randomness; test-only deterministic constructor; opaque consumed nonce pair; no public shared-reference partial signing | default-feature compile, one-shot lifecycle tests, nonce-derivation fuzz target | independent API/zeroization review pending | implemented/tested; gate open |
| Session identifier uniqueness | ratified NAR-002 section 6; ADR-0020 | zero rejection and required storage-owned permanent uniqueness registrar | accept/reject registrar tests | durable G1b implementation/conformance pending | contract implemented; gate open |
| Core/session pre-signature distinction | ratified NAR-002 section 10; ADR-0020 | exact 65-byte core and 162-byte session-bound object | exact length, roundtrip, and cross-length rejection tests | independent vector comparison pending | implemented/tested; gate open |

No checklist box is marked complete in this implementation branch. A checked
box requires a separate gate review that cites the exact code, test command,
fixture provenance, and independent evidence.
