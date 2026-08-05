# G1a/G1b DOM Integration Evidence

Status: **DOM CANDIDATE COMPLETE FOR INDEPENDENT REVIEW — PHASE 1 NOT APPROVED**  
Platform: Linux x86_64  
Branch: `feat/phase-1-integrated`

## Created integration commits

| Commit | Purpose |
|---|---|
| `fb12a0b3512fe35df6d52b2455222b2b052657a6` | integrated canonical cryptography, secret record, vault contract, and type-state signer |
| `3d64671e754b14e340d4d21f48d58dc176489859` | removed caller-selected IDs and caller-forgeable authorized output |
| `94601e32c7883d9fa1327eb35d87ed7983815a56` | exact secret-record and default API evidence |
| `bc77a37859e43ba2eb8adc81b7a1ecb50d9f228e` | one-shot no-copy seal/import ownership capabilities |
| `626f103ce3363901d379d39bc3b19cf0e8cf6a97` | worktree-aware English isolation and gate controls |
| `3fad0af8f193e21ca9c1f3e662d86cabc602112a` | reserve/commit/reveal/partial type-state lifecycle test |

Earlier imported commits remain visible in the branch DAG. No evidence commit
was squashed or rewritten.

## Fresh executed DOM evidence

| Command | Result |
|---|---|
| `cargo check -p dom-adaptor --locked` | exit 0 |
| `cargo test -p dom-adaptor --locked` | 21 unit, 4 adaptor, 7 transcript, 3 freeze, and 6 compile-fail tests passed |
| `cargo clippy -p dom-adaptor --all-targets --locked -- -D warnings` | exit 0 |
| `bash -n scripts/scriptless/*.sh` | exit 0 |
| `./scripts/scriptless/preflight.sh` | exit 0 |
| `./scripts/scriptless/verify-isolation.sh` | exit 0 |
| `./scripts/scriptless/phase1-gate.sh` | expected exit 1: 19 G1a and 26 G1b items open |
| `git diff --check` | exit 0 |

The adaptor tests include all eight SCAD0 records through the real DOM
consensus verifier. The focused integrated lifecycle test exercises internally
allocated IDs, one-shot secret transfer, commitment, reveal, bound partial
verification, durable permit consumption shape, and exact public-byte return.

## Gate adjudication

- G1a: **NOT APPROVED**. The DOM candidate is implemented, but independent
  integrated comparison, long fuzz/sanitizer evidence, and final review remain.
- G1b: **NOT APPROVED**. The DOM contract is implemented, but Wallet
  conformance, fault/process-death evidence, ordinary-Wallet isolation, and
  platform evidence remain.
- Phase 1: **NOT APPROVED**.
- Production: **NOT AUTHORIZED**.

No consensus, existing wire, persisted block, genesis, network magic, PoW,
official repository, remote, release, publication, DL2P source, or real-funds
path was modified or activated.
