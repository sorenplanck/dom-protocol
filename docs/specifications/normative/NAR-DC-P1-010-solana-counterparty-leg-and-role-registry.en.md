# NAR-DC-P1-010 — Solana Counterparty Leg: Mechanism, Chain Kind, Clock, and the Closed Role Registry

Status: **PROPOSED / UNSIGNED / NOT NORMATIVE**

Date: 2026-09-01

Project: DOM Interop / Kaystra counterparty legs

Scope: the Solana condition-lock leg end to end — the third DLEQ role and the
closure of the role space; the lock mechanism tag; the chain kind, cluster
enum, deployment facts and clock; the drift constant its projection carries;
and the SPL restriction. Everything here is implemented and gated in the tree;
nothing here is normative until signed.

This record does not approve production, mainnet-beta, real funds, a release,
or an external security audit. It assigns normative meaning only.

## 1. Authority and ratification effect

This record supplements
`NAR-DC-P1-009-xmr-non-cooperative-refund-adaptor.en.md`
(SHA-256 `cdb68755bfc195fbad90aaf5b5a08189677fa2e3e6c0c77c810da31e50f3ce6b`)
and the eight signed records it in turn supplements.

The detached signature must verify with the established project operator
Minisign public key:

```text
RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
key ID 74197A95CA309CF0
```

Unsigned bytes grant no authority.

## 2. Problem closed

The v8 package implemented a Solana escrow leg that verifies the shared
252-bit witness as an ed25519 discrete log through the curve25519 syscall —
the correct construction, coherent with the Monero leg. But it arrived
mislabelled and unadmitted:

- its DLEQ role byte was `2`, colliding with `ROLE_XMR_REFUND_SHARE`; an XMR
  refund proof verified unchanged as a Solana condition-lock proof (the
  collision was demonstrated executably before the fix, and its negation is
  now a regression test);
- its terms tagged the leg `ConditionLock`, whose ratified meaning is the
  same-curve EVM ecrecover construction that involves no DLEQ at all;
- no `ChainKindV1`, deployment kind, or `ClockKindV2` existed for it, so
  `route-time-anchor` refused every composed route containing the leg as
  `UnsupportedTopology` — fail-closed, and inert;
- `SolanaNetwork::MainnetBeta` was representable while every other chain in
  the branch refuses mainnet by omission.

## 3. Decision

### 3.1 The role registry is closed, and the Solana role is 3

`ROLE_SOLANA_CONDITION_LOCK = 3` is ratified **in `xmr-dleq-sigma`**, beside
roles 1 and 2. The role space is now a single closed table, `ROLES_V1`, in
the one crate that consumes role bytes; no other crate may mint one. A leg
crate re-exports its role from the registry, never defines it.

The static gate (`scripts/solana-v8-static-validate.py`) fails on any
`ROLE_*` constant defined outside the registry, on any duplicate byte, and
on any registry entry missing from `ROLES_V1`; `roles_are_unique_and_nonzero`
holds the same at test time.

Evidence: `every_role_is_distinct`,
`an_xmr_refund_proof_no_longer_verifies_as_a_solana_condition_lock`.

### 3.2 `LockMechanism::CrossCurveConditionLock = 0x06`

Ratified in `kaystra-core`, beside `CrossCurveSharedSpend = 0x05`. The Solana
leg is a discrete-log condition lock **on a curve the DOM leg does not use**,
opened by the same-witness cross-curve DLEQ. It is neither the same-curve EVM
`ConditionLock` (0x02) — using that tag would silently widen a meaning
already signed — nor a shared spend key (0x05): the program enforces its own
timelock refund, so the leg needs no refund adaptor, and the mechanism tag
must not suggest one.

Decode of tag 0x07 still refuses; the frozen set widens by exactly one value.
Existing terms hashes do not move.

Evidence: `the_cross_curve_mechanism_round_trips_and_an_unknown_tag_still_fails_closed`,
`adding_a_mechanism_does_not_move_any_frozen_terms_hash`.

### 3.3 Chain kind, cluster enum, deployment

`ChainKindV1::Solana { network, escrow_program, program_data_hash }` is
ratified in `chain-profile`. The program pinning lives in the kind, beside
the EVM contract pinning, because it is the safety-critical half: a profile
that cannot name the exact immutable program it settles through does not
validate (zero program or zero hash refuses as `UnpinnedCodeHash`).

`SolanaNetworkV1 { Devnet = 0x02, Testnet = 0x03, LocalValidator = 0x04 }` —
**mainnet-beta (0x01) is absent by omission**, exactly as in
`BitcoinNetworkV1` (D-027) and `MoneroNetworkV1`, and the adapter-side
`SolanaNetwork::MainnetBeta` variant is deleted. Enabling mainnet is a
visible change to two enums and this record, not a value someone can pass.
The discriminants of the two spellings are held together by
`network_discriminants_match_chain_profile`.

`ChainDeploymentV1::Solana { genesis_hash, max_fee_lamports }` is ratified in
`deployment-registry`. Solana cluster genesis hashes are live facts, not
source-code derivations (devnet and testnet reset; a local validator mints
its own), so the registry pins whatever nonzero identity the manifest names
and deduplicates on `(network, genesis)`, as EVM does — the program pinning
in the kind carries the trust. A zero fee ceiling refuses.

**SPL restriction:** `allowed_assets` must be empty. The escrow program
supports the legacy token program, but admitting an SPL mint to the registry
needs its own `AssetRepresentationV1` variant and its own ratification.
Until then a profile cannot name one. Native SOL only.

Evidence: `a_solana_profile_validates_and_commits_its_program_pinning`,
`an_unpinned_solana_program_refuses_on_either_half`,
`solana_mainnet_beta_is_unrepresentable_and_refused_on_decode`,
`a_solana_chain_entry_validates_and_round_trips_canonically`,
`solana_deployment_refusals_fail_closed`.

### 3.4 The clock, and the drift band

`ClockKindV2::Solana = 5` is ratified in `route-time-anchor`, with the
admission arm gated on the mechanism:

```text
(ChainKindV1::Solana, ChainDeploymentV1::Solana, TimestampSeconds)
    if mechanism == CrossCurveConditionLock  →  ClockKindV2::Solana
```

Everything else still falls to `UnsupportedTopology`.

Unlike an EVM timestamp, `Clock::unix_timestamp` is a stake-weighted vote
estimate, not a consensus-checked value: its drift *rate* is bounded, its
accumulated offset is not, and the cluster has historically run tens of
minutes behind wall time. Its projection therefore carries a symmetric band:

```text
SOLANA_CLOCK_DRIFT_SECONDS_V2 = 3600
[deadline - 3600, deadline + 3600]
```

One hour covers every observed excursion with margin. The cost of the
conservatism is spacing between a route's legs, never a deadline firing
earlier than proven. Admission accepts only `TimestampSeconds` for this
chain: the escrow's refund clock is the cluster clock and nothing else.

**Repair recorded:** while adding this arm, the Monero clock (`= 4`) was
found bindable but unprojectable — `project_deadline` had no Monero arm and
the codec refused byte 4 — so a composed route with an XMR leg failed closed
at proof time. Monero heights now project through the height arm and decode;
`a_monero_height_deadline_projects_like_the_other_height_clocks` is the
regression test. This corrects an omission in the implementation accompanying
NAR-DC-P1-008; no meaning ratified there changes.

Evidence: `a_solana_timestamp_projects_with_the_drift_band_on_both_sides`,
`a_solana_leg_is_admitted_only_under_cross_curve_condition_lock_and_a_timestamp_deadline`,
`the_solana_mechanism_does_not_leak_onto_the_other_chains`.

## 4. The leg is wired, stored, and tested

Recorded for completeness; none of it needs a signature, all of it is load
bearing for §3 to mean anything.

- `solana-secret-store` keeps the route witness encrypted at rest
  (XChaCha20-Poly1305, AAD-bound to settlement and terms), and
  `resume_session` rebuilds a session after a restart only when the decrypted
  witness reproduces the registered public claim exactly.
- `solana-kaystra-bridge` implements `RevealedSecretSinkV1`: one durable
  `Claim` transaction per settlement, byte-for-byte retransmission from the
  journal, and the stored witness deleted only after the exact signed bytes
  are durable — the XMR sink's discipline, minus the share combination the
  Solana leg does not need.
- `solana-runtime-wiring` installs the sink only after
  `attest_immutable_program` shows, at `Finalized` through the RPC quorum,
  the exact immutable program the setup pins — the gate that
  `production_capable()` plays on the XMR side.
- The on-chain program's native paths now run under test as deployed code
  (syscall-stubbed host harness): claim with the real witness, wrong and
  out-of-domain secrets, substituted state/vault/recipient PDAs, timelock
  refund, double terminal, exact lamport movement, close-after-terminal.
- The program compiles for its real target for the first time:
  `sbf-solana-solana` via platform-tools v1.48, artifact
  `dom_solana_escrow.so`, with the syscall path active
  (`scripts/build-solana-program-v8.sh`; the pinned `Cargo.lock` is the
  reproducibility statement).
- The static gate checks callers, role-registry closure and mainnet absence,
  and demonstrably fails on a disconnected symbol.

## 5. What remains missing regardless of this signature

1. **The syscall on the target cluster.** `sol_curve_group_op` must be
   verified enabled on the cluster you intend to settle on, before anything
   else: `solana feature status --url <cluster>`. If it is not, the design
   does not run there and no amount of the rest matters.
2. **Deployment and pinning.** `program-id.txt` names no real deployment.
   Deploy, record the programdata hash, revoke the upgrade authority, then
   fix profile and registry to those values. Until then
   `attest_immutable_program` has nothing true to attest.
3. **A live-cluster run.** The host harness exercises the processor, not the
   runtime: account creation under the real system program, rent, compute
   budget, and the syscall itself have never executed. A local validator
   pass of initialize → fund → claim and initialize → fund → refund is the
   step that retires this line.
4. **The independent audit**, which now covers three DLEQ roles.
5. **The daemon composition.** `attach_solana_consumer` mirrors
   `attach_xmr_consumer`, and like it, is composed at deployment, not called
   by `dom-interopd` yet — parity with the Monero leg, and a shared gap.

No document in this tree, this record included, authorizes mainnet-beta.
