# Evidence Directory

This directory contains sanitized, commit-bound test reports only. Reports
intended for future publication must omit machine-local paths, secrets,
databases, tokens, and crash artifacts containing memory. Historical success
is never relabeled as execution on a different commit.

Current milestone reports:

- `G1-ADJUDICATION.md` records the coordinator's approval of consolidated
  G1 and the obligations carried past it.
- `PHASE1-CONTRACTS-CLOSURE.md` adjudicates the Contracts-owned G1B/G1C
  candidate and explicitly preserves the external DOM Protocol dependency.
- `G-UX1-PHASE1-BOUNDARY.md` separates the satisfied Phase 1 API and
  release-bypass assignment from the still-pending full G-UX1 stop-ship gate.
- `PORTABLE-PLATFORM-CI.md` records the Windows and macOS evidence matrix and
  keeps it separate from native validation artifacts.
- `STORE-FUZZ-SANITIZER-EVIDENCE.md` preserves the historical campaigns and
  defines the four-target current-candidate renewal gate without relabeling
  old results.
- `NAR-DC-P1-006-RATIFICATION.md` records byte-identical import and detached
  signature verification for the final runtime-authority, Linux platform, and
  evidence-publication closure.
- `NAR-DC-P1-007-RATIFICATION.md` records byte-identical import and detached
  signature verification for the phase-state, two-party roster, and funding
  authority closure: exactly two distinct participants, the 22-edge canonical
  transition table, and the funding-authorisation surface recorded as a model
  rather than production authority.
- `MINIMAL-PERSISTENT-VAULT-ENGINE.md` records the independent-review findings,
  withdrawal of the nonconforming single-reservation experiment from the
  module graph, retained lock hardening, and exact blockers for a future
  production runtime.

Two reports are historical: they describe a tree that no longer exists and are
kept because success is never relabeled onto another commit. Each states its
own supersession.

- `MINIMAL-PERSISTENT-VAULT-ENGINE.md` is superseded by the canonical runtime
  adjudicated in `PHASE1-CONTRACTS-CLOSURE.md`.
- `DOM-ADAPTOR-PIN-VALIDATION.md` records clean reproducibility for the
  superseded pin only; the current pin still requires that execution.
