# NAR-DC-P1-008 — Monero Counterparty Leg: Lock Mechanism and Chain Kind

Status: **PROPOSED / UNSIGNED / NOT NORMATIVE**

Date: 2026-09-01

Project: DOM Interop / Kaystra counterparty legs

Scope: the ratified lock mechanism for a Monero counterparty leg; the chain
kind, network set and deployment facts that make such a leg profileable; and
the admission policy that pairs the two.

This record does not approve production, mainnet, real funds, a release, a
package publication, or an external security audit. It assigns normative
meaning only. It does not attest that a Monero network has been operated, that
a live sweep has been broadcast, or that the GPL sidecar has been reviewed.

## 1. Authority and ratification effect

This record supplements the following signed records:

| Record | SHA-256 |
|---|---|
| `NAR-DC-P1-001-omnibus-gap-closure.en.md` | `88586449d577038ac98e9463250821ed9b3d1e6c94f5b11abfaf036a93eec655` |
| `NAR-DC-P1-002-storage-persistence-closure.en.md` | `719a121c11f4b7f8ea016668bfaa05a3e4d03d3a510df31e3495fb9698560e84` |
| `NAR-DC-P1-003-vault-request-and-recovery-binding.en.md` | `082c855782c71a0f61e85828eaac75440a434d5c05d8357e569592a816db05ef` |
| `NAR-DC-P1-004-live-store-layout-and-runtime-closure.en.md` | `2f9eadb08080844ade7dacfa117a71948ee8a365841fff860d69fe734c42b510` |
| `NAR-DC-P1-005-reservation-runtime-and-linux-capability-closure.en.md` | `4f5582a17426ed5b03d6aa37d6c2fc9cfe564985ec3614d0d4a30fed8ae2d635` |
| `NAR-DC-P1-006-final-runtime-authority-platform-and-evidence-publication-closure.en.md` | `2aa9ec803167f866737375ffbfeca082f98bd1dc9efbefa06c073131bd215a23` |
| `NAR-DC-P1-007-phase-state-participant-and-funding-authority-closure.en.md` | `101ff5e9f3981b47ec038c1772bcc4a6f8849c7f9774a9e1f624fc0880d578e0` |

The detached signature must verify with the established project operator
Minisign public key:

```text
RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
key ID 74197A95CA309CF0
```

Unsigned bytes grant no authority. The implementation described here is present
in the tree and gated closed in the only place it can be reached from — a
Monero chain profile refuses until §4.3 is satisfied — so importing this record
unsigned changes no behaviour.

No existing DOM wire byte, transaction encoding, kernel verifier, genesis value,
network magic, PoW rule, hash domain, or dependency pin is changed by this
record. Section 2.3 states precisely why the settlement terms wire version is
NOT bumped, and the evidence that it did not move.

## 2. Lock mechanism closure

### 2.1 Problem closed

`LockMechanism` had four members, none of which describes Monero. The XMR
adapter profile therefore travelled under `SchnorrAdaptor`, exported as
`KAYSTRA_V1_LAB_ALIAS` with a comment naming it a laboratory alias.

That is a false statement in the object both parties sign. Monero's spend
authority is an ed25519 scalar held as a two-party shared spend key, opened by
a same-witness cross-curve DLEQ proof between secp256k1 and ed25519. It is not
a Schnorr adaptor on the DOM curve, and no adapter can make it into one.

### 2.2 Decision

`LockMechanism::CrossCurveSharedSpend = 0x05` is ratified, defined as: a shared
spend key on a curve the DOM leg does not use, opened by a same-witness
cross-curve DLEQ proof.

`crates/kaystra-core/src/types.rs` — the variant.
`crates/kaystra-core/src/terms.rs` — the `0x05` decoder arm. The encoder needed
no change: `put_leg` writes `mechanism as u8`.

### 2.3 The terms wire version is NOT bumped

An earlier proposal asked for a `TERMS_VERSION` bump, a V2 wire, a retained
strict V1 decoder, and a refusal of silent V1/V2 downgrade. Measured against
the code, the bump is both unnecessary and the more dangerous option.

- `take_mechanism` already refuses any tag it does not know. A decoder built
  before `0x05` existed fails closed on terms that use it. There is no encoding
  an older decoder accepts with a different meaning than a newer one gives it,
  which is precisely the downgrade a version bump exists to prevent. The
  property the proposal asked for is obtained by adding the tag alone.
- `TERMS_VERSION` is inside the canonical bytes and therefore inside
  `terms_hash()`. Bumping it changes the hash of every settlement, including
  the Bitcoin and EVM legs that have nothing to do with Monero, and invalidates
  the frozen vector corpus.

Adding a member to a frozen enumeration widens the accepted set by exactly one
value and opens nothing else. The evidence is a test, not an assertion:
`adding_a_mechanism_does_not_move_any_frozen_terms_hash` re-derives the frozen
vectors and their hashes and requires them unchanged, and
`the_cross_curve_mechanism_round_trips_and_an_unknown_tag_still_fails_closed`
requires `0x06` to remain refused.

## 3. Production gate closure

`XmrAdapterProfileV1::validate_production_v1` previously validated every
binding and then returned `MechanismUnratified` unconditionally. With §2.2 the
refusal has no subject, so the gate is made real:

- `validate_lab_against_terms` requires `KAYSTRA_V1_LAB_ALIAS`;
- `validate_production_v1` requires `CrossCurveSharedSpend`;
- both delegate to one implementation that takes the mechanism as a parameter,
  so the two gates cannot drift apart in what else they check;
- neither accepts the other's terms. `ProfileError::MechanismUnratified` is
  replaced by `MechanismMismatch`, which names what actually went wrong.

Evidence: `neither_gate_accepts_the_other_s_terms`,
`the_production_gate_accepts_the_ratified_mechanism`, and
`a_production_settlement_delivers_end_to_end`, which drives the full
claim-to-sweep path under ratified terms.

## 4. Chain kind closure

### 4.1 Problem closed

`ChainKindV1` had two members, `Evm` and `Bitcoin`. `dom-interopd` admission
matches it exhaustively and pairs each chain kind with the one mechanism and
the timelock domains it accepts. A Monero leg was therefore refused by
admission whatever mechanism tag it carried — a second gate behind the first,
which the mechanism ratification alone would not have opened.

### 4.2 Decision

`ChainKindV1::Monero { network: MoneroNetworkV1 }`, canonical tag `0x03` in the
chain-profile encoding, after `Evm = 0x01` and `Bitcoin = 0x02`.

`MoneroNetworkV1` has `Stagenet = 0x02` and `Testnet = 0x03`. **Mainnet is
absent from the enumeration**, not present-and-refused — the same discipline
as `BitcoinNetworkV1` under D-027 and as EVM chain id 1. Enabling Monero
mainnet is therefore a visible change to this enum and a new record, never a
value a manifest can carry. The discriminants match `xmr_profile::XmrNetworkId`
so the two spellings of "which Monero network" cannot drift; a test pins them
together and requires the adapter's mainnet discriminant to fail to decode as a
registry network.

`ChainDeploymentV1::Monero(MoneroDeploymentV1)` carries exactly two facts:
`genesis_hash`, the chain identity an observer must reproduce, and
`max_fee_piconero`, the route-authorized sweep fee ceiling, which refuses at
zero. The leg holds no contract and no script, so there is nothing else to pin;
everything about a sweep is decided by the adapter profile and proved by the
raw-transaction verifier. A Monero profile with a non-empty allowed-asset list
refuses: Monero's only asset is Monero.

Admission (`counterparty_leg_matches_chain_kind`) admits a Monero leg only
under `CrossCurveSharedSpend` with a `TimelockSpec::BlockHeight` deadline.
Absolute Monero height is the only clock an observer of that chain can evaluate
deterministically. `ClockKindV2::Monero = 4` is the corresponding checkpoint
clock in `route-time-anchor`.

`f7-anchor-authority` is NOT amended. It is the Bitcoin anchor authority — its
policy carries `bitcoin_finality` and it binds `ClockKindV2::Bitcoin` — and a
Monero leg does not pass through it.

Evidence: `a_monero_leg_is_admitted_only_under_the_ratified_mechanism_and_a_height_deadline`
and `the_ratified_mechanism_does_not_leak_onto_the_other_chains`, which
requires that adding a mechanism widened nothing for Bitcoin or EVM.

### 4.3 Ratified Monero genesis values

`RATIFIED_MONERO_GENESIS` in `crates/deployment-registry/src/types.rs` carries:

| Network | Genesis block hash |
|---|---|
| Stagenet | `76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb` |
| Testnet | `48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cda8430b` |

These are **derived, not transcribed**. Bitcoin's canonical genesis is obtained
from `genesis_block(network).block_hash()`; `monero-oxide` exposes no genesis
block, so the equivalent derivation is performed in this repository instead of
borrowed from the library. It is the same construction the Monero daemon uses:
the network's `GENESIS_TX` parsed as the miner transaction, placed in a header
with major version 1, minor version 0, timestamp 0, a zero previous hash and
the network's `GENESIS_NONCE`, and then hashed as a block.

The two inputs come from monero-project's `src/cryptonote_config.h`
(`GENESIS_TX`, and `GENESIS_NONCE` 10001 for testnet and 10002 for stagenet;
testnet reuses mainnet's genesis transaction and differs only in the nonce).

The derivation is corroborated by a second, independent source: monero-project's
own height-0 checkpoints in `src/checkpoints/checkpoints.cpp` — a different file
on a different code path — which carry exactly these two values for TESTNET and
STAGENET.

The constants are held to the derivation by test, not by inspection:

- `the_ratified_genesis_is_the_hash_derived_from_the_genesis_transaction`
  rebuilds each genesis block with `monero-oxide` and requires the table to
  equal the recomputed hash, so a single wrong byte fails the build rather than
  silently repointing chain identity;
- `every_profileable_monero_network_has_a_ratified_genesis` is exhaustive over
  `MoneroNetworkV1`, so adding a network without ratifying its genesis stops
  compiling;
- `the_two_networks_do_not_share_a_genesis` refuses a shared identity, which
  would let a profile for one network accept evidence observed on the other.

`RegistryError::MoneroGenesisUnratified` remains as the residual fail-closed
refusal for a network with no entry. With the table exhaustive it cannot fire
today, which is the intended state.

Monero mainnet has no ratified genesis here because `MoneroNetworkV1` has no
mainnet variant, not because the value is unknown.

## 5. What this record does not decide

- The timing bounds and finality policy of any Monero profile. Those are
  safety-critical configuration under `ChainProfileV1` and are ratified per
  network, with the genesis, under §4.3.
- Whether the GPL sidecar's live sweep constructor may be operated against any
  particular network.
- Anything about Monero mainnet, which remains unrepresentable.
