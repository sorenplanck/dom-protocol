# DOM Protocol Focal Runtime and Convergence Audit

Baseline: `task21-clean-from-preintegration` at `4c12d8d5f6bfd4b03aa8d7ab2697f63b231c6684`.

## A. TASK 19 - NodeTaskSupervisor Integration

`NodeTaskSupervisor` is present in `crates/dom-node/src/task_supervisor.rs` and exported from `crates/dom-node/src/lib.rs`. It already tracks task handles, exposes a shutdown token, records task failures, and has ordered shutdown tests.

It is not wired into the live `DomNode::run` path at baseline. `crates/dom-node/src/node.rs` still spawns long-lived production tasks directly:

| Spawn site | Classification | Baseline issue |
| --- | --- | --- |
| P2P listener in `DomNode::run` | critical | Bare `tokio::spawn`; clean exit only logs via select. |
| outbound peer connector in `DomNode::run` | critical | Bare `tokio::spawn`; failure can silently degrade networking. |
| miner loop in `DomNode::run` | critical when mining enabled | Detached; unexpected exit is only logged inside miner. |
| RPC server in `DomNode::run` | critical operational service | Detached; bind is checked but runtime failure does not shut down node. |
| future-block queue drain in `DomNode::run` | critical convergence service | Detached infinite loop. |
| Dandelion stem-timeout promoter in `DomNode::run` | critical transaction relay service | Detached infinite loop. |
| inbound peer session in `run_p2p_listener_on` | operational per-peer | Detached; cleanup is present but not supervised. |
| outbound peer session in `run_peer_connector` | operational per-peer | Detached; cleanup is present but not supervised. |

Critical loops not supervised: P2P listener, outbound connector, miner, RPC, future-block replay queue, Dandelion stem promoter.

## B. TASK 20 - Live Shutdown/Cancellation

`ShutdownToken` exists in `task_supervisor.rs`, and `shutdown_ordered` can request shutdown, join tasks by phase, and abort tasks after a bounded grace period.

At baseline the live runtime does not pass the token into:

| Component | Baseline token use |
| --- | --- |
| P2P listener | no |
| peer connector | no |
| miner | no |
| RPC server | no |
| future-block queue drain | no |
| Dandelion stem/fluff timeout loop | no |
| inbound peer sessions | no |
| outbound peer sessions | no |
| per-peer cleanup tasks | no |

`DomNode::run` waits only for listener or connector completion and then returns `Ok(())`. It does not coordinate shutdown of the other tasks, and it does not convert critical task failure into a returned error.

## C. TASK 8 - Orphan Handling

There is a dedicated orphan pool module at `crates/dom-chain/src/orphan_pool.rs`, and `MissingBlockTracker` exists in `crates/dom-node/src/missing_block_tracker.rs`. The current live node path primarily handles child-before-parent behavior through chain side-block storage plus missing-block request tracking.

Baseline gaps:

| Question | Baseline finding |
| --- | --- |
| Dedicated live orphan pool? | Present in chain crate, but not clearly the live node's single orphan model. |
| Child-before-parent handling | Chain can retain known side blocks and node can request missing parents, but the equivalence is not documented as the node-level orphan model. |
| Orphan/future/invalid/side-chain separation | Future blocks have a separate queue; invalid blocks are rejected; side chains are stored, but tests need to prove the separation explicitly. |
| Memory bounds | Future queue and missing tracker are bounded; orphan side-block storage bounds need explicit proof/coverage. |
| Peer spam scoring | Malformed/invalid relay paths score peers in several places, but orphan spam scoring is not clearly proven by a single test. |

## D. TASK 14/15 - IBD/Reorg Live Coverage

The repository contains deterministic chain/reorg tests and node/integration IBD tests, but the baseline grep still shows ignored or environment-separated IBD/reorg coverage. Meaningful live coverage should not exist only behind `#[ignore]` or VPS-only assumptions.

Required follow-up: identify ignored tests precisely during implementation and add CI-safe deterministic coverage for late join IBD, restart/resume, live or harnessed reorg convergence, and reorg-after-restart invariants.

## E. TASK 16 - Multi-Node Reordered Delivery

No explicit `crates/dom-node/tests/multinode_reordered_delivery.rs` file exists at baseline. Existing missing-block and side-chain behavior provide partial coverage, but there is no direct test whose scenario is child block delivered before parent, parent later delivered, child reprocessed, common tip reached, and no orphan/request leak remains.

Required follow-up: add an explicit deterministic reordered-delivery test or a harnessed equivalent that proves child-before-parent handling and convergence without arbitrary sleeps.
