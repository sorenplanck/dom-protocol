# Post-mortem: equal-height fork divergence and network fragmentation

**Date of incident:** 22–23 July 2026
**Severity:** network partition (multiple chains coexisting, no reconciliation)
**Fix commit:** `5fad708` — resolve equal-height fork divergence
**Status:** resolved

---

## Summary

Nodes at the **same height but on different tips** never reconciled. The chain
sync logic initiated a download only when a peer announced a *greater* height,
so a peer at equal height on a different branch was treated as having nothing to
offer. Once two branches existed at the same height, each node continued mining
its own, and the network fragmented into islands that could not converge.

Observed fragmentation points: heights **5389** and **5782**. At height 5782 the
divergence was directly confirmed by hash comparison — one branch carried tip
`eaab202e…` while the canonical chain carried `0380f6ea…` at the same height.

This is distinct from the difficulty incident documented separately. The chain
was *producing* blocks; it was producing them on several chains at once.

---

## Triggering condition

Two nodes reach the same height on different tips. This arises normally from:

- near-simultaneous block propagation, where two miners find a block at the same
  height and different parts of the network see a different one first
- recovery from a network partition, where each side advanced independently
- a node returning from downtime onto a branch that has since been superseded

None of these are adversarial. They are expected conditions in any proof-of-work
network, and the protocol is supposed to resolve them by preferring the chain
with the most accumulated work.

---

## The invariant that failed

**Assumed:** *a node converges on the most-work chain whenever it encounters a
peer on a different chain.*

**Implemented:** a node initiated chain download only when
`peer_height > local_height`.

The implementation used **height as a proxy for accumulated work**. Those are the
same thing only when all nodes are on the same chain — which is precisely the
condition that fails during a fork. At equal height with different tips, the
comparison returned "no action needed," and neither node ever evaluated which
branch carried more work.

The consequence is worse than a missed opportunity: because each island kept
mining its own branch, the divergence was *self-reinforcing*. Nodes on the stale
branch stayed there indefinitely, and no amount of waiting resolved it.

---

## Why the existing test suite did not detect it

This is the part worth reading, and it is checkable against the repository.

A two-node integration suite **already existed** at
`crates/dom-integration-tests/tests/ibd_two_node.rs`, and it was not thin. It
covered:

| Test | Case |
|---|---|
| `t1_ibd_through_randomx_epoch_boundary_via_three_real_nodes` (line 519) | Sync across a RandomX epoch boundary, three real nodes |
| `t2_ibd_with_active_miner_relay_during_sync` (line 640) | Sync while a miner is actively relaying new blocks |
| `t3_ibd_noise_fragmentation_headers_above_one_frame` (line 701) | Header batches exceeding one Noise frame |
| `t7_ibd_restart_resume_after_interruption` (line 999) | Resuming sync after interruption |

Every one of these is a *peer-ahead* scenario. The node is behind, or catching up,
or resuming — and in each case the height comparison the implementation used was
the correct signal. The suite exercised the sync machinery thoroughly along the
axis the design assumed mattered.

There was no case where two nodes stood at **equal height on different tips**.
`5fad708` added it: `t4_equal_height_divergent_nodes_converge` (line 749, with
its async form at 756). The commit *modified* this file rather than creating it —
77 lines changed, with insertions and deletions — which is the concrete evidence
that the suite predated the fix and simply had no such case.

So the gap was not sparse coverage. It was that the tests and the implementation
encoded the same model of correctness — *behind means sync, level means done* —
and a test derived from a flawed model cannot contradict the flaw. The missing
test and the missing code path were the same omission expressed twice.

## The fix

`5fad708` makes fork resolution depend on accumulated work rather than height
alone. A node encountering a peer at equal height with a different tip now
compares accumulated work and reorganises onto the heavier branch if the peer's
is heavier.

This is a network-layer and chain-selection change; it does not alter block
validity rules, so it required no activation height and carried no fork risk of
its own. However, a node cannot benefit from it without running the new binary —
which is why fragmentation persisted for days after the fix was published, among
operators who had not updated.

---

## Regression evidence

Added by `5fad708`:

- **Integration:** `t4_equal_height_divergent_nodes_converge` —
  `crates/dom-integration-tests/tests/ibd_two_node.rs:749` (async form at 756).
  Two real nodes are driven to equal height on divergent tips and must converge.
- **Unit:** `equal_height_different_tip_requires_fork_resolution` —
  `crates/dom-node/src/node.rs:8002`. Pins the decision directly: equal height
  with a differing tip must route to fork resolution rather than to "nothing to
  do."
- The fix introduced `sync_mode_for_peer(...)` as the explicit decision point, so
  the peer-comparison policy is one named function with a test against it, rather
  than an inline height check.

Supporting invariants that already existed and now carry more weight:

- `crates/dom-chain/src/kani_invariants.rs:23` —
  `production_fork_choice_matches_work_then_canonical_hash_order`
- `crates/dom-chain/src/kani_invariants.rs:43` —
  `equal_work_fork_choice_is_total_antisymmetric_and_deterministic`

These are Kani proof harnesses over fork choice, i.e. the *selection* rule was
formally checked. That is worth stating precisely, because it locates the bug
exactly: fork choice was correct. What was missing was ever *invoking* it in the
equal-height case. A verified comparator is inert if nothing calls it.

Also relevant: `crates/dom-node/src/node.rs:7705` —
`persisted_ibd_snapshot_is_rejected_when_tip_hash_changed_at_same_height`, which
covers the adjacent hazard of resuming from a checkpoint whose tip hash moved
under the same height.

## Recovery was not automatic for already-diverged nodes

Worth recording, because it affects anyone operating a node that fell behind.

A node that had already synced part of a divergent branch could not always
recover by updating alone. On one seed node, restarting with the fixed binary
did not reconcile: the checkpoint mechanism failed to resolve a **missing
ancestor** error, because the local database contained a branch whose history did
not connect to the canonical chain in a way the checkpoint could bridge.

Recovery required backing up the divergent database and **resyncing from
genesis**. The reset also generated a new Noise identity for that node, changing
its `peer_id` — harmless in itself, but surprising if you are tracking nodes by
identity.

---

## Where the system remains fragile

Stated for contributors deciding where to work:

- **Fork detection is unmonitored.** The fragmentation was found by manually
  comparing announced heights and hashes across peers. There is no tooling that
  detects "peers at equal height with differing tips" and raises it. This is a
  contained, well-defined piece of work with clear value.

- **Recovery from a diverged database is manual.** As above: the automatic path
  can fail with a missing-ancestor error, and the remedy is operator
  intervention. A repair path that detects the condition and resyncs cleanly
  would remove that.

- **Peer discovery was independently broken during this period.** The peer
  exchange layer accepted and re-propagated any syntactically valid `ip:port`,
  including non-routable ranges (RFC 1918, RFC 2544 benchmark space), and
  refreshed `last_seen` on every re-announcement so dead addresses stayed
  permanently "fresh". This starved real peer discovery and materially slowed
  convergence. Fixed subsequently with routability filtering on both ingress and
  egress, inbound peer learning, and `last_seen` discipline — but the episode
  shows that consensus recovery depends on the discovery layer being healthy,
  and the two were being reasoned about separately.

- **Consensus updates depend on operators acting.** There is no automatic
  propagation for standalone nodes. The desktop wallet now self-updates, which
  covers that population; terminal operators still require an announcement and a
  manual update plus restart.

---

## Operational lesson

The same one as the first incident, and it is the reason fragmentation outlived
the fix: **updating source without restarting the service leaves the old binary
running in memory.** A node that had pulled the fix but not restarted was
indistinguishable, from the outside, from a node that had ignored the
announcement entirely.
