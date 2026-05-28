# VPS role: devnet/backbone runtime only

The DOM Protocol VPS is **not** the place to run heavy mining-based test
suites. Mining tests, multi-node integration tests, reorg fuzz, and IBD
exercises belong on a developer Windows machine (using
`dom-test-runner.exe`) or on GitHub Actions (via the Windows runner
workflow).

## What the VPS is for

- Running a stable `dom-node` instance on devnet / future controlled
  testnet, contributing to backbone availability.
- Pulling approved code from GitHub `main` and restarting cleanly.
- Long-running burn-in evidence collection (uptime, block continuity,
  resource ceilings, log archives).
- Acting as a reproducible reference node for community sync experiments
  when the public testnet is opened.

## What the VPS is NOT for

- Running `cargo test --workspace` under mining pressure.
- Multi-process two-node / three-node integration tests.
- Reorg fuzz, IBD restart fuzz, mempool relay race tests.
- Anything where slow CPU mining inflates test duration past
  reasonable bounds.

## Suggested flow

```
[Windows + Codex]
  → dom-agent-runner.exe run --prompt-file prompts/X.txt --push
  → dom-test-runner.exe affected / pre-push (already gated)
       ↓ on green
  → git push origin main
       ↓
[GitHub]
  → Actions: windows-test-runner.yml validates on windows-latest
  → Actions: windows-agent-runner.yml builds + doctor
       ↓ on green merge into main
[VPS]
  → systemctl stop dom-node
  → git pull --ff-only
  → cargo build --release
  → systemctl start dom-node
  → tail/monitor logs; archive burn-in evidence
```

Treat the VPS as the **runtime layer**, not the **validation layer**.
Heavy validation is too slow on most VPS CPUs and competes for the same
cores the node needs for steady operation.
