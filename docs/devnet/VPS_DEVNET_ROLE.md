# VPS Devnet Role

The VPS should be used for devnet/backbone runtime only.

Heavy mining, replay, reorg, restart, and multi-node validation should run on Windows through `dom-test-runner.exe`, with GitHub Actions building portable artifacts for distribution.

Recommended flow:

1. Windows or Codex runs local development and validation.
2. `dom-test-runner.exe` runs the relevant tests.
3. `dom-agent-runner.exe` commits and pushes approved changes.
4. GitHub becomes the source of truth.
5. The VPS pulls approved code and restarts the devnet/backbone runtime.

The VPS should not be the primary machine for heavy mining or long integration validation unless there is no other option.
