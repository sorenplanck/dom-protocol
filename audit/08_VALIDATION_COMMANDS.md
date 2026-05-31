# DOM Protocol Validation Commands

## Purpose

This file defines validation commands that should be run after audits, patches, or security-related changes.

## Baseline Commands

Run from repository root:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Targeted Commands

Use these when relevant crates exist:

```bash
cargo test -p dom-chain
cargo test -p dom-crypto
cargo test -p dom-node
cargo test -p dom-wallet
cargo test -p dom-mempool
cargo test -p dom-p2p
cargo test -p dom-miner
```

## Security-Oriented Searches

```bash
rg "unwrap\(|expect\(|panic!\(|todo!\(|unimplemented!\(" .
rg "bypass|skip|insecure|debug|test_only|allow_invalid|disable_validation" .
rg "unsafe" .
```

## Git and Diff Hygiene

```bash
git status --short
git diff --stat
git diff --check
git log --oneline -n 10
```

## Recommended Additional Checks

If available in the repo:

```bash
cargo test --workspace --features fuzz
cargo test --workspace --features proptest
cargo audit
cargo deny check
```

## Validation Report Requirement

Every final report must state:

- Which commands were run.
- Which passed.
- Which failed.
- Exact failure summary.
- Whether failures are related to the current changes or pre-existing baseline issues.

