# Declaration of the real state of the tree — 2026-08-19

Prepared for signature alongside the D-019 amendment v2. Every line is a
measurement taken when this file was written, not a recollection.

## Commits that exist, and what they touch

```text
Dom-interop-f7  (HEAD = 2c08283)
    2c08283 2026-08-19 15:05  Carry the ratified D-019 amendment through the registry tests
    c2d4c2f 2026-08-19 13:46  Make the gate green: formatting, feature gating, and one dead method
    690af4e 2026-08-19 13:16  Make the refund terminal reachable, and reach it
  published to origin/main: 43 commits ahead, 0 pushed

dom-contracts-f7  (HEAD = 105b9b0)
    105b9b0 2026-08-19 15:05  Record the operator's 2026-08-19 ratification of the M.8 funding-resume fix
  published to origin/main: 9 commits ahead, 0 pushed

```

## What each commit changed, by file

```text
690af4e
   crates/adapters/btc-live/src/funding.rs |  62 +++++++++++++
   crates/adapters/dom-real/src/lib.rs     |  25 +++++
   crates/dom-leg/src/f7_live_wallet.rs    |  17 +++-
   crates/dom-leg/src/f7_route.rs          |  21 ++++-
   crates/f7-runner/src/lib.rs             |  55 +++++++++--
   crates/f7-runner/src/live_bitcoin.rs    |  77 ++++++++++++++++
   crates/f7-runner/src/live_executor.rs   | 156 +++++++++++++++++++++++++++++---

c2d4c2f
   crates/adapters/btc-live/src/funding.rs | 62 ---------------------------------
   crates/f7-runner/src/live_bitcoin.rs    | 21 -----------
   crates/f7-runner/src/live_executor.rs   |  9 ++---
   crates/f7-runner/src/live_relay.rs      | 12 +++++--
   crates/f7-runner/src/live_route.rs      |  4 +--

2c08283
   crates/relay/src/auth.rs                       | 29 +++++++++++++-------------
   crates/relay/tests/d019_message_type_policy.rs | 23 +++++++++++++-------

105b9b0
   crates/dom-scriptless-store/src/runtime/linux/session_store.rs | 5 +++--
```

## What the test suite asserts today

```text
  registry size assertion : assert_eq!(known, 5
  t05 reserved probe      : INVALID, 0x0006, 0xffff
  is_known kinds          : 7 references to ROUTE_TRANSPORT in auth.rs
```

## Normative text still in force

```text
  v0.18 line 1712 (context authority today):
                   0x0005..0xffff = RESERVED/UNKNOWN in V1

  §12.1 highest decision recorded: D-028 (2026-08-12)
  D-029: does not exist in any version in force
```

## Gate state

```text
  four gate runs launched 2026-08-19; none produced a CI-LOCAL EXIT
  run c (over c2d4c2f): stopped, two concurrent gates — D-20260819T000145Z
  run d (over 2c08283): stopped by operator order, 180 min, 10 of 12 steps
                        green, halted because the workspace-tests step rests
                        on the mirror whose provenance is in question
  host verified clear of every ci_local.sh, cargo and test binary by PID
```

## Statement

No source file in any worktree has been modified since `2c08283` and
`105b9b0`. Nothing has been pushed to any remote. The five documents in
this package are the only artefacts produced since the operator halted the
gate, and none of them has been applied to the tree.
