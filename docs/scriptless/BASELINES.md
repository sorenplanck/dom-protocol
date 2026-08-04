# Baselines

## DOM

- Read-only source: `/home/leonardov/dom-release`
- Source branch: `release/mainnet`
- Base commit: `769822562565f18ef55423dc992e7aa661206b4a`
- Tree: `9cee98e2d393d52b7a330e398a04216f98f4f339`
- Local annotated tag: `baseline/scriptless-2026-08-04`
- Isolated branch: `feat/phase-1-dom-adaptor`

## Wallet V3 v0.3.2

- Read-only source: `/home/leonardov/dom-wallet-v3`
- Source branch: `redesign/restore-remote-scan`
- Current base commit: `1868e61bc39eca223d794348d70e48668ad06708`
- Current tree: `5c572e4b5d083dbb7caa0ca608c0d2864add9f6c`
- Version: `0.3.2` from the workspace `Cargo.toml`
- Current local annotated tag: `baseline/scriptless-wallet-v0.3.2-2026-08-04`
- Isolated branch: `feat/scriptless-integration`

The previous baseline remains preserved:

- Previous commit: `abb573168be75b23269343559e4e94e28e9d33e7`
- Previous tree: `b4cba9f9677dc5d48a5a8f5ac3c072a28a0a9fcd`
- Previous annotated tag: `baseline/scriptless-wallet-2026-08-04`

The isolated Wallet branch moved from the previous baseline to v0.3.2 only by
fast-forward. The current HEAD and tree are byte-identical to the committed
official Wallet state recorded on 2026-08-04. The three known untracked reports
in the official Wallet are not part of either baseline and were not imported.

Baselines always refer to committed `HEAD` trees. Untracked source files do not
belong to them.
