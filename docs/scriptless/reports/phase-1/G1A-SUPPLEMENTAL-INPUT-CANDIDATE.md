# G1a supplemental two-party input candidate

Date: 2026-08-04

Status: **RATIFIED — OUTPUT GENERATION AUTHORIZED**

Branch: `test/phase-1-independent-vectors-ratified`

## Candidate

The input-only supplemental fixture is:

```text
test-vectors/scriptless/two-nonce/kat_two_party_adaptor_inputs_v1.en.json
```

Content SHA-256:

```text
5e5063e819e7d64514039905c3c9fed0cb98c39f36c370fdb4c413751a08fac9
```

Expected detached signature:

```text
test-vectors/scriptless/two-nonce/kat_two_party_adaptor_inputs_v1.en.json.minisig
```

The exact content verified with the declared DOM release Minisign key. The
detached signature SHA-256 is
`2f0fc550cda61ffb9377f1ce0055fbe9196bc9bcdf0406eb868cda89ce8df7ed`.
Minisign returned exit 0 with trusted timestamp `1785875781`.

## Contents

The fixture supplies two canonical secret shares and their validated compressed
SEC1 public keys, distinct auxiliary-randomness inputs, both participant indexes
and role-stable directions, a strictly ordered roster, per-participant retry
counters, complete ratified context fields, canonical adaptor secret and point,
aggregate-excess inputs, exact kernel challenge chain and message inputs, one
base case, eight accepted mutations, and twenty negative mutations.

It contains no expected cryptographic output. In particular, it does not contain
derived secret nonces, public nonces, commitments, binding factors, aggregate
points, challenges, partial signatures, pre-signatures, final signatures, or
extracted secrets.

## Validation

The evidence-only validator is:

```text
test-vectors/scriptless/two-nonce/independent/ratified-v1/validate_supplemental_inputs.py
```

Validator SHA-256:

```text
6516c951a29887e367116f696290aa6d54834c294716389febbf63d774ecd073
```

Command:

```text
python3 test-vectors/scriptless/two-nonce/independent/ratified-v1/validate_supplemental_inputs.py
```

Result:

```text
supplemental input fixture valid: 1 base + 8 accepted mutations; 20 rejected mutations
no expected cryptographic outputs generated
```

Validation checks exact scalar ranges, scalar/public-key correspondence,
canonical SEC1 decoding and re-encoding, adaptor secret/point correspondence,
ordered and unique roster membership, participant indexes, role assignment,
context discriminants and lengths, aggregate-excess input ordering, nonidentity
aggregate excess, and exact challenge/context chain and message agreement.

## Independence

No G1a implementation source, commit, report, or output was inspected. The
candidate uses only ratified NAR-001, accepted ADR-0013, signed KAT conventions,
and the authoritative DOM tagged-hash and Schnorr challenge definitions. It is
ratified for independent output generation. No production comparison had
occurred when ratification was recorded.
