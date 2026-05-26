# Chain Persistence Latency RCA

Status: confirmed operational RCA, 2026-05-26.

This note records the investigation into
`crates/dom-integration-tests/tests/chain_persistence.rs::test_chain_persists_across_restart`
after the test exceeded Cargo's 60-second "still running" threshold.

## Scope

The question was whether the delay came from:

- restart / reopen behavior
- replay or PMMR recovery
- LMDB reopen / filesystem locking
- clock health startup checks
- or block production cost during the test setup itself

The investigation treated restart and recovery as potentially consensus-relevant
until the execution path proved otherwise.

## Reproducer

Command:

```bash
cargo test -p dom-integration-tests test_chain_persists_across_restart -- --nocapture
```

Observed pre-fix runtime:

- the test completed successfully
- total runtime was about 103 seconds
- Cargo emitted the standard "has been running for over 60 seconds" warning

## Execution Path Isolation

The test was instrumented in three stages:

1. `spawn_node` on first boot
2. `mine_blocks(&node, 1)`
3. `spawn_node` on second boot against the same `data_dir`

Observed timings from the instrumented run:

- first `DomNode::init`: about 0.11-0.13s
- `mine_blocks(&node, 1)`: dominant cost
- second `DomNode::init` / reopen: not the dominant cost

This eliminated the following as primary causes for the stall:

- `ChainState::open`
- LMDB reopen / filesystem handle contention
- replay or PMMR rebuild during restart
- restart equivalence checks on the reopened store

## Narrowed Cause

Further instrumentation inside `mine_one_block()` and `mine_blocking()` showed:

- coinbase construction: about 0.05s
- PMMR root computation: about 0.05s
- RandomX cache/VM initialization in Regtest cache-only mode: about 6.16s
- first RandomX hash produced: about 6.20s

The remaining delay was therefore not startup, not reopen, and not replay. It
was proof-of-work search time after the VM became ready.

## Root Cause

The stall had two operational contributors:

1. Regtest mining was incorrectly using the full-memory RandomX path in
   `crates/dom-node/src/miner.rs` even though the surrounding comments and test
   expectations assumed the cache-only path.
2. The Regtest target was incorrectly treated in comments as "instant" or
   "first nonce wins", but the actual target semantics do not provide zero-work
   mining.

`REGTEST_TRIVIAL_TARGET_DO_NOT_USE_IN_PRODUCTION` is currently equal to
`MAX_TARGET_BYTES`.

That target is consensus-valid and very easy, but it is not a bypass target.
Because `MAX_TARGET_BYTES` begins with two leading zero bytes, a uniformly
distributed 32-byte RandomX hash satisfies it with probability about `2^-16`.

Operational consequence:

- expected work is on the order of 65,536 hashes, not one hash
- even with cache-only RandomX, mining one block can legitimately cross the
  60-second warning threshold on a modest VPS or constrained dev host

## Cache-Only vs Full-Memory

RandomX mode matters operationally:

- cache-only VM:
  - about 256 MB working set
  - slower hashes
  - appropriate for Regtest and test harnesses
- full-memory VM:
  - multi-gigabyte dataset allocation
  - better throughput
  - inappropriate for low-effort Regtest block setup

The correction committed in `b3734c2` forces Regtest to stay on the cache-only
path and adds a regression test pinning that network selection.

## Why This Was Not Replay / Recovery

The investigation excluded replay and recovery as the dominant failure surface:

- first init was fast
- reopen on the same `data_dir` was not where time accumulated
- the delay started before restart, inside the initial block production path
- coinbase, PMMR root derivation, and post-mine `connect_block` were not the
  long pole

The test's warning threshold was crossed because block production in the setup
phase was expensive, not because restart semantics were incorrect.

That distinction matters:

- operational latency in test bootstrapping is not the same class of problem as
  replay divergence
- restart/recovery correctness should not be weakened or "optimized away" in
  response to a mining-cost issue

## Secondary Latency Surface

`DomNode::init` still performs synchronous clock health checks.

In network-restricted or NTP-unreachable environments, each SNTP source can
consume its full timeout budget before returning `Unknown`. That did not prove
to be the dominant cost in this RCA, but it remains an operational startup
latency surface worth treating as hostile-environment-sensitive.

## Follow-Up Guidance

- keep startup timing surfaces measurable
- keep Regtest runtime behavior explicitly bounded and documented
- do not classify long-running integration tests as replay/recovery failures
  before separating PoW, I/O, reopen, and diagnostics costs
- treat clock health, RandomX initialization, filesystem reopen, and restart
  synchronization paths as independent operational risk surfaces
