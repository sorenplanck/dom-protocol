# DOM Adaptor Immutable Pin Validation History

Status: `HISTORICAL_PASS_SUPERSEDED_BY_CURRENT_PIN`

Current DOM Protocol revision:
`6f2b230ebbec390040dbf0bff110efaf4bb0f101`

Current DOM Protocol tree:
`7b22395a3d1a1c3d8eac84c376643cffd7ce7bb5`

The clean reproducibility execution recorded below belongs to the historical
revision `180b731a6aeba37f03a74fb49e985bf8741d0885`, tree
`a45ef6fc0f8db0a01decb210b234fae9daf111cc`, as consumed by DOM Contracts
commit `2e61edecfa0a616e6f545eaea67dcd3bcea5bca1`. It is preserved as historical
evidence and is not relabeled as execution on the current pin.

## Public object identity

The public repository resolves the current immutable revision from
`https://github.com/sorenplanck/dom-protocol`. The Contracts manifests pin both
`dom-adaptor` and `dom-crypto` to the same complete revision. The root and fuzz
lockfiles record that same full Git object for every imported DOM package.

No production manifest contains an absolute path, sibling-worktree override,
`[patch]`, floating branch, or unpublished revision. The ordinary DOM Wallet
is not a dependency.

## Historical clean reproducibility execution

A separate `git clone --no-local` of the validated Contracts commit used an
initially empty task-specific Cargo home and target directory. It fetched the
DOM dependency from the public Git URL; no local source override or cached Git
object was available.

The following commands all exited `0`:

| Command | Result |
| --- | --- |
| `cargo metadata --locked --format-version 1` | immutable public revision resolved |
| `cargo fmt --all -- --check` | pass |
| `cargo check --workspace --all-targets --locked` | pass |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | pass |
| `cargo test --workspace --all-features --locked` | 137 top-level tests passed; 3 subprocess helpers ignored by the parent harness |
| `cargo build -p dom-scriptless-wallet --bin dom-contracts --release --locked` | pass |
| native fail-closed validation shell execution | pass |
| `git diff --check` | pass |
| `git status --short` | empty |

The slow authenticated-envelope mutation test passed in 647.40 seconds in the
clean execution. The Linux Store suite passed 116 tests; its three ignored
entries are subprocess helper entry points exercised by their parent tests,
not omitted validation cases.

## Scope

This historical evidence validates public dependency pinning and clean local
reproducibility only for the historical revision named above. Current-pin
reproducibility is adjudicated separately by the Phase 1 closure evidence. No
part of this record approves production, real funds, mainnet, Phase 2, or a
release.
