# DOM Protocol 0.2.0 — Mainnet hard fork v3

This is the single release note for the Mainnet v3 hard fork and its network
synchronization fixes.

## Mandatory upgrade

Mainnet activates block version 3 at height **12,500**.

- Height 12,499 and below requires block version 2.
- Height 12,500 and above requires block version 3.
- A v3 block before activation is invalid.
- A v2 block at or above activation is invalid, regardless of accumulated work.
- Block validity is checked before accumulated-work fork choice. A post-fork v2
  branch never competes with a valid branch.
- Mining selects the required version from the next block height automatically.
- Existing genesis identities and pre-activation history are unchanged.

Nodes that remain on the legacy release will still establish P2P connections,
but they will not follow the valid Mainnet chain after height 12,500.

## Rolling finality

Rolling finality is active immediately when this binary starts; it does not
wait for height 12,500.

- An established local chain accepts reorg depth 359.
- Reorg depth 360 or greater is refused even if the candidate is valid and has
  more accumulated work.
- A refused deep reorg emits a WARN containing its depth, local tip and refused
  tip.
- A fresh or short node can still perform initial block download from genesis.
- Normal chain extension is unchanged.

## Wire compatibility and node identity

`WIRE_PROTOCOL_VERSION` remains **2**. The hard fork is enforced through block
validity, not by splitting the Hello handshake.

The workspace package version is **0.2.0**. `dom-node` advertises the package
version in Hello as:

```text
dom-node/0.2.0
```

Operators can therefore distinguish this v3-capable build by user-agent while
legacy and upgraded nodes continue using wire protocol 2.

## Network synchronization and reputation fixes

This release:

> corrige seeds sendo banidos durante a sincronização inicial (rajada de
> re-requisições após IBD longa); penalidades de peer passam a expirar de fato;
> erros locais deixam de penalizar peers.

Detailed behavior:

- Catch-up timers use `MissedTickBehavior::Skip`; ticks missed during a long IBD
  are collapsed instead of replayed as a burst.
- Every Tokio interval in the Cargo workspace has an explicit `Skip` policy and
  an in-code justification.
- Requested `Block` responses are classified as synchronization traffic rather
  than unsolicited block relay.
- Synchronization traffic above its window budget is paced/throttled and never
  adds ban score.
- Non-sync excess can add ban score at most once per category/window, rather
  than once per message.
- The `GetBlockData` wire envelope remains compatible at 128 hashes, while the
  server sends at most **16 block bodies per request**.
- IPs currently resolved from explicit `DOM_SEED_PEERS` entries are never
  rejected by the pending-penalty threshold.
- Seed hostnames are resolved again during connector passes. A successful DNS
  change replaces stale IP immunity; a temporary lookup failure preserves the
  last successful result.
- Reputation remains keyed by IP, preserving protection against port rotation.
- Persisted peer reputation v2 stores the actual expiry timestamp. Restarting a
  node no longer renews a 15-minute penalty.
- Legacy reputation records, which did not store age, migrate as expired.
- A pending penalty is removed when it causes registration rejection, so the
  same record cannot reject and renew forever.
- Crossing `BAN_THRESHOLD` emits a structured WARN with peer, accumulated score
  and reason.
- Malformed messages, invalid PoW, invalid signatures and other real abuse still
  accumulate score and can ban a peer.

## IBD checkpoint migration

The local IBD session metadata is versioned as `ibd_session/v2`.

- A valid legacy `ibd_session` is migrated automatically.
- Corrupt, incompatible or inconsistent local checkpoint data is discarded.
- Synchronization then restarts from the canonical local tip.
- Local database/checkpoint errors are not attributed to the remote peer and do
  not affect peer reputation.

## Offline reputation cleanup

The release includes:

```text
dom-peer-reputation-clear <node-data-dir>
```

Run it only while the node using that data directory is stopped. It removes
both v1 and v2 peer-reputation metadata. This is an operator recovery tool; the
normal v2 migration and expiry logic do not require routine manual cleanup.

## Required public notice

> Hard fork at height 12,500; v2 nodes will not follow the chain after that
> height; rolling finality of 360 blocks. Upgrade to DOM Protocol 0.2.0 before
> activation.

The remaining-time estimate must be recalculated from the current observer
height immediately before publishing. At the target cadence, each remaining
block represents approximately two minutes.

## Release assets

The release tag is `v0.2.0`. The draft is created with:

- `dom-node`;
- `dom-node.sha256`.

**Operator signature pending:** `dom-node.minisig` must be generated and
uploaded by the release operator before the draft is published. The Minisign
private key is not handled by the build or publication agent.

The complete publication and infrastructure-update procedure is in
`docs/RELEASE_V3_RUNBOOK.md`.

## Upgrade

Stop the current node, replace it with the signed 0.2.0 release binary, and
restart it using the same configuration and data directory. Confirm that peer
logs show user-agent `dom-node/0.2.0`.

Do not reset the data directory. The release preserves the existing genesis and
chain history, migrates supported local metadata, and resumes from the stored
tip.

## Validation completed for the release candidate

The release-relevant source tree must pass before publication:

- full protocol, node and Wallet V3 dependency test coverage;
- the seven-scenario real `ibd_two_node` suite;
- `shield_ban_port_rotation_kav.rs`;
- message-rate-limit integration tests;
- `dom-wire` eclipse-resistance suite;
- IBD persistence and corruption tests;
- workspace build for all targets;
- release build and SHA-256 calculation.

The retired legacy wallet is not part of the 0.2.0 release gate. Its removal
and test-suite cleanup are explicitly deferred until after this release.

The release artifact must be built from the exact revision pinned by downstream
wallet builds.

## Rollout order

1. Complete the full automated suite and the agreed real-node test.
2. Build the release artifact from the final revision.
3. Sign the artifact with the notebook Minisign key.
4. Tag the exact release revision and publish these notes with the artifact,
   signature and SHA-256 digest.
5. Update seed1, seed2, the observer and the notebook miner immediately.
6. Advance every DOM Protocol crate pin and embedded-node revision in Wallet V3
   to the exact published node revision. Resolve the wallet restore-parity
   blocker before publishing the wallet.
7. Announce height 12,500, the current remaining-time estimate, the release URL
   and the one-command upgrade instruction on Discord, Telegram, Bitcointalk
   and GitHub.
8. Pin the Discord notice and obtain explicit confirmation from the largest
   miners.
9. At height 12,500, monitor observer height, block cadence, peer user-agents and
   rolling-finality WARN events on both seeds.

## Release invariants

- `MAINNET_V3_ACTIVATION_HEIGHT = 12_500`
- `MAX_REORG_DEPTH = 360`
- `WIRE_PROTOCOL_VERSION = 2`
- workspace/package version `0.2.0`
- Hello user-agent `dom-node/0.2.0`
- no genesis change
