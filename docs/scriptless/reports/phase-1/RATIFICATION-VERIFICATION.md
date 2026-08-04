# NAR-001 and ADR-SNV-001 Ratification Verification

Date: 2026-08-04  
Repository: DOM Scriptless Contracts isolated development clone  
Verification status: **VALID**

## Verification authority

- Scheme: Minisign detached signatures
- Key ID: `74197A95CA309CF0`
- Public key: `RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`
- Wallet evidence: `crates/dom-wallet-updater/examples/feed_tool.rs:27-28` at official Wallet baseline `1868e61bc39eca223d794348d70e48668ad06708`

The private signing key was not opened, hashed, copied, logged, or used by the verification process.

## Verified artifacts

| Artifact | Content SHA-256 | Signature SHA-256 | Trusted timestamp | Verification |
|---|---|---|---|---|
| `docs/scriptless/source-guides/normative/amendments/NAR-001-normative-assignment-record.en.md` | `eee087c808aeb4e6e745a5311d17ca5a63c5b5e5568218d20b1cbcdd7b6206dc` | `6d1ef078a7de411e11acb1873cb1742d968ebb1a7a44629be66035d086ad2691` | `2026-08-04T17:04:00-03:00` | valid, exit 0 |
| `docs/scriptless/source-guides/normative/amendments/ADR-SNV-001-witness-and-aad.en.md` | `3939df85814e8c2b1fad8ea6484492887000b38917c3b23e47d5d505311270c2` | `5dac59c0c2c203402a51a7ba2941519f652c7ed5b19f221d38b5d703f7a2dd0a` | `2026-08-04T17:01:21-03:00` | valid, exit 0 |
| `test-vectors/scriptless/two-nonce/kat_inputs_v2.en.json` | `55642208968863a7b2c4773a82d9774f95f2a3b604b80a876d0bf031396b2a7d` | `1341e3ceecb55755f4321b47007fa2af624de92fcb5561bb8674cd640f2c6190` | `2026-08-04T17:01:33-03:00` | valid, exit 0 |

## Command

Each artifact was verified independently with:

```text
minisign -Vm <artifact> -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

For all three artifacts, Minisign reported:

```text
Signature and comment signature verified
```

and returned exit code `0`.

## Normative effect

The detached signatures satisfy the ratification condition printed in each candidate. Consequently:

- NAR-001 is an effective normative assignment under its declared authority order;
- ADR-SNV-001 is an effective G1b protocol/AAD decision;
- the KAT input fixture is frozen as an authenticated input-only fixture;
- any later byte modification requires a new signature and a manifest update;
- ratification freezes inputs but does not by itself approve G1a, G1b, Phase 1, production activation, or real-funds use.

## Integrity and scope

The three signed contents retain the exact pre-signing review hashes. Their detached signatures are tracked separately in the normative/vector manifests. No official repository was modified, and no push, merge, release, publication, consensus change, wire change, DL2P import, or real-funds authorization occurred during verification.
