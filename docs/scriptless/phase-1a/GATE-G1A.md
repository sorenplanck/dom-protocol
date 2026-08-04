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
| Hash framing and commitment | ADR-0011/0012 | `nonce_commitment_hash_v1` | critical-field differential tests | Python-frozen tagged vectors cover backend framing | open pending complete transcript |
| Collective binding | ADR-0013 | `binding_factor_v1`, `BindingFactorV1` | exact frozen binding digest and grammar/order negatives | hash byte vector is independent; full scheme is not | open |
| Bound partial verification | ADR-0013/0017 | `PartialSignatureV1::verify_bound` and `dom_crypto::scriptless_verify_bound_partial` | authoritative DOM challenge test | independent aggregation vectors absent | open |
| Adaptor verify/adapt/extract | EM/RC, ADR-0014/0017 | `AdaptorPreSignatureV1` and `dom-crypto::scriptless` | all eight SCAD0 records and negative mutations | SCAD0 provenance remains correlated | open |
| Real final verifier | ADR-0014 | unchanged `schnorr_verify`; test-only consensus wrapper | all eight final kernels pass `validate_kernel_signatures` | consensus path is authoritative | implemented/tested; gate remains open with adaptor row |
| Secret handling | ADR-0009/0017 | opaque non-Clone/non-Debug `AdaptorSecret` and `ScriptlessSecretScalar`, `ZeroizeOnDrop` | compile-time API shape and behavior tests | dedicated audit absent | open |
| Parsers | ADR-0010/0011 | exact fixed-width fail-closed parsers and persistent libFuzzer targets | bounded panic/malformed/mutation tests; short Linux ASan campaigns | no independent parser review; canonical context parser blocked | open |
| Wide scalar reduction | mission decision; ADR-0018 | `dom_crypto::scalar_from_wide_be` delegates to constant-time `k256::Scalar::Reduce<U512>` inside the authoritative owner | zero, one, `n`, `n+1`, and high-bit tests | dedicated audit absent | implemented/tested; gate remains open with KDF row |
| Closed-cycle property | adaptor equations; ADR-0017 | existing authoritative boundary | 10,000 deterministic adapt/extract cycles; every final signature passed the real DOM verifier and every extraction passed `tG=T` | implementation-generated, not independent | implemented/tested; independent validation open |
| Secret two-nonce derivation | blocked by ADR-0013/0018 | deliberately absent | none | no independent vectors | blocked on explicit DirectionV1 and PhaseV1 bytes |

No checklist box is marked complete in this implementation branch. A checked
box requires a separate gate review that cites the exact code, test command,
fixture provenance, and independent evidence.
