# DOM — Bug Bounty Policy (Phase 8.4)

Status: pre-launch policy draft. Activated when the public
testnet (Phase 8.1) goes live and rewards switch to live DOM at
mainnet launch.

## Scope

In scope:

* Consensus-class bugs — anything that lets a non-authorized
  party invalidate honest blocks, accept invalid blocks, or
  produce a chain split between honest implementations of the
  same spec.
* Cryptographic soundness bugs — forgery, key recovery, range
  proof break, commitment binding violation.
* Storage bugs that survive `commit_block`'s atomicity contract
  (RFC-0007 §14).
* Wire / P2P bugs — eclipse, replay, resource exhaustion that
  the existing Phase 4.x caps fail to block.
* Wallet bugs that leak secret material or let one party spend
  another's outputs.
* RPC bugs that let a remote (without the bearer token) trigger
  privileged operations.
* RFC ambiguities that could lead two independent implementers
  to diverge on consensus.

Out of scope:

* Bugs requiring physical access to the operator's machine.
* Social-engineering attacks against operators / maintainers.
* Bugs in pure UI / explorer / faucet code (not consensus).
* Bugs in upstream dependencies — report to the upstream first;
  if DOM is mis-using the dependency, that counts.
* DoS attacks below the documented resource-cap thresholds
  (e.g. flooding a peer with `MAX_HEADERS_PER_MSG` headers is
  expected; flooding past the cap and getting them accepted is
  a bug).

## Severity tiers

* **CRITICAL** — Direct chainstate forgery, key recovery,
  supply inflation, or a consensus split between two honest
  nodes running the released binary.
  Reward: 50 000 DOM (post-launch) / equivalent fiat pre-launch.

* **HIGH** — Eclipse / partition that succeeds against the
  documented defences (Phase 4.x), unbounded memory growth past
  the resource caps, signature malleability that leads to a
  re-org, race conditions in `connect_block` that corrupt
  state under realistic timing.
  Reward: 10 000 DOM / equivalent.

* **IMPORTANT** — Liveness bugs (single node halts under valid
  peer inputs), missing input validation that doesn't lead to
  consensus break, mempool-policy bypasses below the relay
  floor, slowloris / handshake-stall variants beyond the
  documented timeouts.
  Reward: 2 000 DOM / equivalent.

* **LOW** — Documentation / RFC drift, weak logging, missing
  CI gates, code-quality issues that don't have a clear
  security impact.
  Reward: 200 DOM / equivalent or zero, at maintainer
  discretion.

Reward amounts are placeholders; finalised in the engagement
letter at testnet launch.

## Submission protocol

1. Reproducer required. A claim without a reproducer is not a
   submission — it's a hypothesis. Hypothesis-level claims may
   be acknowledged but do not earn payouts.
2. Reproducer MUST be deterministic. Property-test seeds,
   fuzz-input bytes, and the exact `cargo` invocation reach the
   maintainer alongside the report.
3. Encrypted to the maintainer's PGP key (published in the
   release tag's signing-key entry).
4. Coordinated disclosure window: 90 days from acknowledgement
   for CRITICAL / HIGH, 30 days for IMPORTANT / LOW. The
   maintainer commits to a public advisory at the end of the
   window regardless of fix status.
5. Public PoCs MUST NOT be released before the window closes,
   even if a fix is already shipped — peers running older
   binaries are still vulnerable.

## What gets disclosed publicly

After the disclosure window:

* A CVE-style identifier (DOM-YYYY-NNNN).
* The location, root cause, fix commit hash.
* A timeline from report → fix → release → public advisory.
* The reporter's chosen attribution (handle / real name /
  anonymous).
* Reward payout (in DOM amount; not the legal-name banking
  information of the reporter).

## Exclusions

The bounty does NOT pay for:

* Bugs already known to the maintainer (recorded in
  RELEASE_BLOCKERS.md or an open GitHub issue at the moment
  of submission). Duplicate-finding is acknowledged but not
  paid.
* Bugs in code clearly marked `#[doc(hidden)]` or `pub(crate)`
  and intended as test-only infrastructure.
* Bugs in the env-blocked integration tests
  (`crates/dom-integration-tests/`) when triggered by a
  non-conforming test environment (these tests are documented
  to need a dedicated mining host).

## Confidentiality

* The maintainer commits to not sharing the report contents
  with any third party (auditors, peers, infrastructure
  operators) before the disclosure window closes, except
  on a strict need-to-know basis under the same confidentiality
  terms.
* The reporter MAY share with their own employer / counsel
  during the window; they MUST inform the maintainer if doing
  so.

## Pre-launch operation (testnet phase)

During Phase 8.1 (public adversarial testnet) the bounty pays
in fiat-equivalent for confirmed findings. Same severity /
window structure. Reports here are especially valuable because
they catch bugs before the genesis ceremony (Phase 8.5) freezes
the protocol.

## Contact

Until the maintainer publishes a dedicated security email and
PGP key in the first signed release:

* Email: `leovictor157@hotmail.com` (subject prefix `[DOM
  SECURITY]`)
* Out of scope for now: anonymous tipline, hardware-token-based
  signed-disclosure. Both are Phase 8.4 follow-ups.
