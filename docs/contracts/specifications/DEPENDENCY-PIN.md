# DOM Adapter Dependency Pin

Status: `PINNED_AND_LOCALLY_VALIDATED`

Every DOM Protocol package this workspace consumes is pinned to the same
immutable public DOM Core revision:

```text
repository: https://github.com/sorenplanck/dom-protocol
revision:   6f2b230ebbec390040dbf0bff110efaf4bb0f101
tree:       7b22395a3d1a1c3d8eac84c376643cffd7ce7bb5
branch:     feat/dom-protocol-g1a-crypto-closure
```

The full revision was independently resolved from the public remote before
this pin was introduced. Production manifests contain no absolute path,
sibling-worktree override, floating branch, or unpublished revision.

## The pinned set

| Package | Consumer | Kind | Purpose |
|---|---|---|---|
| `dom-adaptor` | `dom-scriptless-crypto`, `dom-scriptless-store` | production | Canonical adaptor codec and verifier; Phase 1 authority |
| `dom-crypto` | `dom-scriptless-crypto` | production | Authoritative hash and signature boundary |
| `dom-core` | `dom-scriptless-store` | production | Canonical core types |
| `dom-consensus` | `dom-scriptless-crypto` | dev only | Reads the frozen 115-byte SCAD0 kernel with the canonical codec |
| `dom-serialization` | `dom-scriptless-crypto` | dev only | Supplies the canonical deserialization trait for the above |

`dom-consensus` and `dom-serialization` are dev-dependencies. No production
code links either one, and the fixtures they read are imported bytes recorded
in `crates/dom-scriptless-crypto/tests/fixtures/PROVENANCE.md`. They exist so
frozen vectors are parsed with the canonical codec instead of by byte offset;
reading a signed fixture with a second, locally written parser would be the
same defect this pin exists to prevent.

`dom-consensus` is a node-side crate. It is compiled only into this
workspace's test binaries, so the product still embeds no miner and no full
node, and no runtime path reaches consensus logic. That boundary is the
README's, and it is unchanged.

`scripts/check-boundaries.sh` verifies the revision for this whole set, and
fails on any `dom-*` git dependency not listed in it, so a new package cannot
quietly introduce a second pin.

Neither dependency introduces any relationship with the ordinary DOM Wallet.
