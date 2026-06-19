# Security Policy

DOM is pre-launch and under active adversarial hardening. Security is the first
priority of the project, ahead of stability and usability. Responsible disclosure
is welcome and valued.

## Reporting a vulnerability

**Do not open a public issue for security-sensitive findings.** A consensus,
cryptographic, or memory-safety bug disclosed publicly before a fix is in place
can be exploited against anyone running the software.

Instead, report privately:

- **Email:** sorenplanck@tutamail.com

Please include enough detail to reproduce the issue: the affected component, the
conditions that trigger it, and — if possible — a minimal reproducer. If you have
a proposed fix or mitigation, include it; it is helpful but not required.

## Scope

The consensus-critical core carries the highest priority:

- **Inflation** — any path that lets value be created outside the issuance
  schedule (balance equation, kernel aggregation, range proofs).
- **Double-spend** — any path that lets the same output be spent twice.
- **Consensus divergence** — any input that makes honest nodes disagree on the
  chain state.
- **Memory safety / denial of service** — any untrusted input (a transaction,
  block, proof, or network message) that crashes a node or corrupts its state.

Privacy weaknesses, peer-to-peer resource exhaustion, and wallet fund-safety
issues are also in scope, at lower priority than the consensus core.

## What to expect

Reports are reviewed and reproduced before any conclusion is drawn. A finding is
treated as a measured engineering fact: confirmed, scoped, and fixed with a
regression test that prevents it from returning. There is no bug-bounty program at
this stage; this is an invitation to responsible disclosure, not a paid program.
