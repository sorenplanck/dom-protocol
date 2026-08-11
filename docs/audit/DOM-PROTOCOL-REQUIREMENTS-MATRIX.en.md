# DOM Protocol — Requirements Matrix

Canonical branch: `release/mainnet` @ `7698225`. Audit line: `feat/dom-contracts` @ `6141eac`.

`VERIFIED_COMPLETE` requires reachability from the canonical branch. No
Scriptless code is reachable from it, so **that status is currently held by zero
`DSC-*` requirements**. This is an integration fact, not a judgement on code
quality: the implementation exists, is tested, and its integration is a verified
fast-forward held only by a permission blocker (see `NORMATIVE-GAPS`).

| Req | Source | Implementation | Tests reproduced | Status |
| --- | --- | --- | --- | --- |
| DSC-F1 adaptor presign/adapt/extract, `t·G=T` | Mestra §6 | `adaptor.rs` | yes, incl. closed-cycle property | IMPLEMENTED_UNVERIFIED |
| DSC-F1 canonical vectors (SCAD0) | Mestra §15.2 | `7698225` | on canonical branch | **VERIFIED_COMPLETE** |
| DSC-F1 two-nonce binding `R_i=R_i1+b·R_i2` | Mestra §6.6 | `transcript.rs`, `signing_round.rs` | yes | IMPLEMENTED_UNVERIFIED |
| DSC-F2 §4.2 share PoK | Mestra §4.2 | `share_pop.rs` | yes | IMPLEMENTED_UNVERIFIED |
| DSC-F2 codecs, transcript, anti-replay | Mestra §8 | `contract_session.rs`, `messages.rs` | yes | IMPLEMENTED_UNVERIFIED |
| DSC-F2 §8.5 equivocation fail-closed | Mestra §8.5 | `contract_session.rs` `FailedClosed` | yes | IMPLEMENTED_UNVERIFIED |
| DSC-F3 `SessionRecordV1` authority record | Mestra §10.1 | dom-contracts `canonical/session.rs` | yes, 8 tests | IMPLEMENTED_UNVERIFIED |
| DSC-F3 CAS + irreversibility | Mestra §10.1/§10.3 | `advance()` | yes | IMPLEMENTED_UNVERIFIED |
| DSC-F3 atomic write under crash | Mestra §10.5 | runtime/linux | not run — needs harness | BLOCKED_EXTERNAL |
| DSC-F4 joint blinding `C=vH+ΣR_i` | Mestra §4.3 | `collaborative_output.rs` | yes | IMPLEMENTED_UNVERIFIED |
| DSC-F4 collaborative BP driver | Mestra §5.4/§5.5 | `collaborative_range_proof.rs` | yes, 739-byte proof via consensus verifier | IMPLEMENTED_UNVERIFIED |
| DSC-F4 mandatory proof matrix | Mestra §5.7 | `bp_mandatory_matrix.rs` | yes, 7 tests | IMPLEMENTED_UNVERIFIED |
| DSC-F4 deterministic decoy capsule | Mestra §12.3 | `decoy_capsule.rs` | yes | IMPLEMENTED_UNVERIFIED |
| DSC-F5 funding order, refund-before-funding | Mestra §7.2/§7.3 | `funding_authority.rs` (`ClaimPresigned` gate) | yes | IMPLEMENTED_UNVERIFIED |
| DSC-F5 height-locked kernels | — | `19c191f`, `76597c6` | on canonical branch | **VERIFIED_COMPLETE** |
| DSC-F5 CPFP fee bump | Mestra §7.6 | `fee_bump.rs` | yes, 7 tests | IMPLEMENTED_UNVERIFIED |
| DSC-F5 fee ladder under live relay | Cronograma 4.3 | — | — | BLOCKED_EXTERNAL |
| DSC-F6 claim floor / deadline | Mestra §7.5 | `contract_session.rs` | yes | IMPLEMENTED_UNVERIFIED |
| DSC-F6 `Exposed` irreversible, I-F5 | Mestra §11 | `chain_projection.rs` | yes, 7 tests | IMPLEMENTED_UNVERIFIED |
| §3.4 frozen hash-domain registry | Mestra §3.4 | `domain_tag.rs`, `docs/HASH_DOMAINS.md` | yes, differential + frozen vectors | IMPLEMENTED_UNVERIFIED |
| DSC-G0/G2/G3/G4/G5 | Mestra §15.7 etc. | — | need running nodes | BLOCKED_EXTERNAL |
| UX-01,02,04,05,06,11,12,14,15,16 | Adendo §9 | — | application layer absent | MISSING |
| UX-03,07,08,09,10,13 | Adendo §9 | supporting primitives only | partial | PARTIAL |
| SET-F6, F4-POLICY, Keystone, routing | — | 0 files | — | MISSING (other repository) |
| G-COVER | Mestra §15.8 | — | calendar | BLOCKED_EXTERNAL |
