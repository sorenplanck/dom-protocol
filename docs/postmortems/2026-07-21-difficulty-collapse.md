# Post-mortem: mainnet difficulty collapse and stall

**Date of incident:** 21–22 July 2026
**Severity:** chain halt (no new blocks accepted network-wide)
**Fix commit:** `065e484` — mainnet ASERT rescue hard fork
**Activation height:** 4849
**Status:** resolved

---

## Summary

The mainnet chain stalled at height **4848**. Block 4849 took **4,285 seconds
(71.4 minutes)** to arrive, against a 120-second target — 35.7x over.

The root cause was the difficulty adjustment algorithm failing to recover from an
abrupt drop in network hashrate on a low-participation network: once difficulty
had been set too high relative to remaining hashrate, the time to find the next
block stretched far beyond target, and the adjustment window could not close fast
enough to correct itself.

The fix was a hard fork replacing the adjustment algorithm with ASERT
(absolutely scheduled exponentially rising targets), activating at height 4849.

---

## Triggering condition

A large share of network hashrate left within a short window while the network
had few participants. With a small total hashrate, a single miner leaving
represents a large proportional drop — far larger than the adjustment algorithm
was designed to absorb between retargets.

The result is a feedback trap: difficulty is calibrated to hashrate that no
longer exists, block intervals stretch, and because retargeting depends on
blocks being *found*, the algorithm cannot correct until a block arrives that
may take orders of magnitude longer than the target interval.

### Measured intervals

Derived from block timestamps via the `/block/<height>` RPC route on a node with
full history — reproducible by any reader with a synced node.

| Height | Interval since previous block |
|---:|---:|
| 4841–4848 | 120s each |
| **4849** | **4,285s (71.4 min)** |
| 4850 | 33s |
| 4851 | 4s |
| 4852 | 2s |
| 4853 | 2s |
| 4854 | 6s |
| 4855 | 2s |
| 4856 | 1s |
| 4857 | 6s |
| 4858 | 1s |
| 4859 | 2s |
| 4860 | 7s |

Three things are visible here.

**The stall.** 71.4 minutes for one block. This matches the threshold encoded in
the regression test that now guards the case:
`one_hour_without_a_block_relaxes_enough_to_restart_a_small_network`.

**The overshoot.** Blocks 4851–4860 arrived in 1–7 seconds. The rescue relaxed
the target far enough to make mining briefly trivial before re-hardening. This
is the mirror-image hazard, and it is why
`abrupt_hashrate_entry_hardens_instead_of_sticking_to_the_easy_floor` exists as a
separate test — a rescue that only loosens converts a halt into a different
failure.

**An unexplained regularity.** Blocks 4841–4848 each show *exactly* 120 seconds.
Proof-of-work block intervals are exponentially distributed; eight consecutive
intervals landing exactly on target is not natural variance. The likely
explanations are timestamp clamping or a monotonicity rule normalising recorded
times, but this has not been confirmed against the code. It is recorded here as
an open question rather than explained away — if the timestamps in that range are
normalised rather than observed, then the pre-stall intervals in this table are
not measurements of when blocks were actually found, and anyone reasoning about
that window should know it.

### Convergence afterwards

A second sample, roughly a hundred blocks later, shows the network settling rather
than oscillating:

| Height | Interval | | Height | Interval |
|---:|---:|---|---:|---:|
| 4941 | 56s | | 4949 | 122s |
| 4942 | 75s | | 4950 | 39s |
| 4943 | 225s | | 4951 | 122s |
| 4944 | 121s | | 4952 | 264s |
| 4945 | 79s | | 4953 | 63s |
| 4946 | 10s | | 4954 | 95s |
| 4947 | 73s | | 4955 | 96s |
| 4948 | 131s | | | |

Mean is close to target with wide variance — 10s at the fast end, 264s at the
slow. For a network with few miners this is the expected shape: individual
intervals are exponentially distributed, so high variance around a correct mean is
health, not malfunction. No stall recurred in this window.

This matters for interpreting the incident. There was **one** stall, at 4848→4849.
Earlier internal notes referred to a second stall around height 4946; the
timestamp data does not support that, and the claim is withdrawn here.

### On attributing the 71 minutes

Height 4849 is also the fork activation height. The 4,285-second gap therefore
contains two things that timestamps alone cannot separate: the algorithmic delay
before the target relaxed enough for remaining hashrate, and the human time spent
diagnosing and deploying the fix. Distinguishing them would require correlating
against deployment timestamps. The figure is reported as measured, not as a pure
algorithmic latency.

## The invariant that failed

**Assumed:** *the difficulty adjustment converges toward the target block time
under realistic hashrate variation.*

This held under gradual hashrate change. It did not hold under an abrupt
withdrawal of a large proportional share on a network with few miners — a
regime that a young chain occupies by definition, and that a mature chain
essentially never does.

The deeper error was importing an implicit assumption from large-network
conditions: that hashrate changes are smooth relative to the retarget window.
On a small network that assumption is false, and the algorithm has no floor
behaviour for the case where it has already over-tightened.

---

## Why the existing test suite did not detect it

The difficulty tests exercised **steady-state and gradually varying hashrate**.
They asserted that the algorithm converges toward the target interval, which it
does under those inputs.

No test simulated:

- an abrupt loss of a large proportional share of hashrate
- the resulting stall, i.e. an inter-block interval orders of magnitude beyond
  target
- recovery *from* an over-tightened difficulty rather than convergence *toward*
  a correct one

The test suite validated the algorithm's intended behaviour. It did not model
the adversarial or degenerate regime in which the algorithm's assumptions break.
This is the general shape of the gap: the tests encoded the same assumption the
implementation did, so they could not contradict it.

---

## The fix

`065e484` replaces the previous adjustment with **ASERT**, activating at height
4849. ASERT computes the target from absolute elapsed time against a schedule
rather than from fixed-window averages, so it responds proportionally to how
late a block is instead of waiting for a window to close. This removes the trap
where a stall prevents the correction that would end the stall.

Because this changes block validity rules, it is a **hard fork**. Nodes running
a binary from before `065e484` reject every block after the activation height
with:

```
invalid compact target: target > MAX_TARGET
```

This error is therefore diagnostic: a node reporting it is running a pre-fork
binary, not experiencing a network fault.

---

## Regression evidence

`065e484` added a new test file, `crates/dom-pow/tests/mainnet_asert_rescue.rs`
(120 lines, new), covering the failure mode directly:

| Test | What it pins down |
|---|---|
| `rescue_is_height_gated_and_preserves_pre_activation_history` | The fork activates only at 4849 and does not retroactively invalidate earlier blocks |
| `one_hour_without_a_block_relaxes_enough_to_restart_a_small_network` | The stall condition itself: after an hour with no block, the target relaxes enough for a small network to resume |
| `abrupt_hashrate_exit_then_return_converges_without_a_manual_reset` | The exact trigger — a large proportional hashrate exit followed by return — now converges without operator intervention |
| `abrupt_hashrate_entry_hardens_instead_of_sticking_to_the_easy_floor` | The inverse risk: the rescue must not leave difficulty pinned at a floor once hashrate returns |

The last two are the pair that matter. The original failure was a one-way trap:
difficulty could over-tighten and had no path back. A naive rescue creates the
mirror-image trap — difficulty stuck too loose, trivially mineable. Both
directions are now pinned by test.

Related adversarial coverage exists in
`crates/dom-pow/tests/asert_adversarial.rs`, including
`oscillating_arrivals_do_not_diverge` (line 217), which exercises repeated
alternating block-arrival timing rather than a single step change.

## Where the system remains fragile

Stated for contributors deciding where to work:

- **Low-participation dynamics are covered by unit test, not by simulation.**
  The tests above pin specific scenarios with fixed inputs. The chain currently
  operates in exactly the regime where the original algorithm failed, and the
  interesting question is no longer "does the rescue work" but "what is the
  boundary." Property-based or simulated-network testing across a range of
  hashrate swing magnitudes and frequencies would map that boundary; today it is
  known only at the sampled points.

- **No automated stall detection.** Both incidents were found by a human reading
  logs. There is no monitor that alerts when inter-block interval exceeds a
  threshold, which is the earliest observable signal of this class of failure.

- **Hard-fork coordination is manual.** A consensus change requires every node
  operator to update *and restart*; see the second post-mortem for how that
  failed in practice.

---

## Operational lesson

Updating source without restarting the service leaves the previous binary
running in memory. Several nodes — including one operated by the maintainer —
appeared stuck after "updating" for this reason. All subsequent consensus
announcements state the restart requirement explicitly.
