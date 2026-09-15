# DOM↔EVM + DOM↔BTC — measured gate map up to `dom-interopd run --create`

Single machine, regtest + anvil. Every gate below was crossed by executing the
real release-production daemon and reading the refusal it printed, not by
inferring from the source.

## 1. What is already proven live (below the daemon)

`crates/f5-e2e/tests/composed_route_live.rs` — both scenarios green against a
real `anvil` and a real Bitcoin Core regtest node, in both directions:

- EVM→BTC: the route scalar `t` is revealed by `ConditionLockV2.claim`, observed
  from the receipt, carried to regtest where it adapts a MuSig2 2-of-2
  pre-signature prepared without `t`; the claim is broadcast, mined, and `t` is
  re-extracted from the confirmed witness bytes byte-identically
  (`extracted_equals_observed=true`).
- BTC→EVM: the reverse (`evm_republished_equals_bitcoin_extracted=true`).

Recipe:

```text
cargo test -p f5-e2e --test composed_route_live --no-run
anvil --port 8547 --chain-id 31337 --silent &
COMPOSED_EVM_RPC=http://127.0.0.1:8547 \
  cargo test -p f5-e2e --test composed_route_live -- --ignored --nocapture --test-threads=1
```

`--test-threads=1` is required: two concurrent regtest nodes exhaust memory on
a small host.

This coverage lives below the daemon. Nothing else in the repository drives the
`dom-interopd` binary against a live chain; that step is what the rest of this
report maps.

## 2. `crates/dom-route-ceremony`

A standalone workspace (same reason and same exclusion treatment as
`deploy-genconfig`). From the local deployment mold written by
`scripts/deploy-local-v1.sh` it produces, through the daemon's own validated
writers:

1. the registry manifest, signed by a fresh 2-of-3 authority set, installed and
   re-verified;
2. both `SettlementTermsV1` (upstream DOM↔EVM `ConditionLock` +
   `TimestampSeconds`, downstream DOM↔BTC `SchnorrAdaptor` + `BtcTime512s`);
3. the route-time policy derived from the registry and its first evidence, each
   threshold-signed by an independent authority set;
4. the durable V2 time anchor, the proven ladder, the composed binding and the
   **route admission**;
5. the nine `inputs/` artifacts;
6. `bootstrap-create-v10.conf` and `bootstrap-reopen-v10.conf`;
7. `production-relay-network.v1`.

```text
KEEP=1 scripts/deploy-local-v1.sh
cargo build --manifest-path crates/dom-route-ceremony/Cargo.toml
crates/dom-route-ceremony/target/debug/dom-route-ceremony \
  testnet/local-deploy/deploy-local-manifest.v1.json <state-dir>
```

Independent cross-check: `network_id`, `dom_chain_id` and
`registry_manifest_digest` come out byte-identical to what `deploy-genconfig`
produces along its own path.

## 3. Gates crossed, in order

| # | gate | result |
|---|---|---|
| 1 | operational artifact (`production && release && linux`) | pass |
| 2 | V3 secret stream on stdin | pass |
| 3 | local EVM credential | pass |
| 4 | V10 bootstrap config, 28-path layout, F6 V4/V8, auxiliary inputs | pass |
| 5 | `production-relay-network.v1` (two Noise links) | pass |
| 6 | authenticated `inputs/` | stops at the Contracts bootstrap |

## 4. The gate that needs the second party

`inputs/contracts-bootstrap.v1` must be exactly 2 594 bytes
(`1194` commit + `4×64` + `832` reveal + `4×64`). It is a two-stage
commit/reveal ceremony with four BIP-340 signatures per stage, the reveal bound
to the commit digest, carrying a 96-byte recovery capsule, 33-byte share points
and per-participant Schnorr keys. `authenticate_against_expected_v1` refuses to
interpret the reveal before the commit authenticates under both Relay keys.

It is the product of a real exchange between the two parties and is
deliberately not synthesized here: reconstructing it from the verifier alone
would yield bytes that pass verification without carrying the protocol's
meaning.

## 5. Calibration traps, each measured

1. **F6 HSM credential count of 0** in the secret stream: `parse_hsm_count_v3`
   requires `1..=16`; zero is refused behind the same opaque message as every
   other secret error.
2. **Hub margin below its floor**: with the local timing (reorg 600 s,
   observation 30 s, broadcast 20 s) `minimum_safety_margin_seconds` is 1 300;
   the component fixture's 60 was calibrated for a 20 s reorg.
3. **DOM deadlines inherited from the fixture**: 400/200 blocks assume a 2 s DOM
   block. At 30 s per block `prove_rung` refuses
   (`upstream.earliest ≥ downstream.latest + margin` fails by ~4 710 s). The fix
   is to widen the deadline gap (8 000/200), never to relax the margin, because
   the margin sits on the penalizing side of that inequality.
4. **Positional secret stream**: fields are newline-delimited with no redundant
   framing; a shell helper that omits a newline silently merges two 64-hex
   fields and yields a field-count refusal.

## 6. Operator-facing observation

Refusals are precise inside and opaque outside: `ProductionInputErrorV1` has
fifteen named variants (`ContractsBootstrapRefused`, `PinMismatch`,
`TimeRefused`, …), but `run_production_v1` maps them all to "production inputs
refused". The secret stream behaves the same way. Surfacing the variant would
save whoever operates this a great deal of bisection.

## 7. What the second machine must bring

- its half of the Contracts bootstrap ceremony (signed commit and reveal);
- its own `production-relay-network.v1` with the Noise roles inverted
  (`Connect` ↔ `Listen`) and the Relay database identities crossed;
- only its own participant keys — the single-machine rehearsal holds both
  sides' keys, which is acceptable for a rehearsal and never for production.
