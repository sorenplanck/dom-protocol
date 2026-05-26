# Consensus-Critical Hardening RCA

Status: investigation + first correction snapshot, 2026-05-26.

This document records hardening items that are treated as CONSENSUS-CRITICAL
until explicitly approved. It separates confirmed code behavior from likely or
theoretical consequences. Do not use this document as approval to change
consensus, serialization, replay, PMMR, validator, chain-selection, or wire
compatibility semantics.

## Approval Boundary

The following categories require explicit user approval before implementation:

- chain selection semantics
- persistence ordering
- replay behavior
- validator behavior
- kernel uniqueness enforcement
- IBD acceptance semantics
- PMMR root semantics
- wire compatibility or parser acceptance semantics

Safe work while approval is pending: analysis, documentation, fuzz harnesses,
non-semantic tests that pin current behavior, diagnostics, and operational
tooling that does not change acceptance rules.

## Finding A: Side-Chain Persistence Can Rewrite Canonical Pointers

Classification: confirmed, existential, consensus-critical.

Correction status: hardened in the current working tree.

Affected files:

- `crates/dom-chain/src/chain_state.rs`
- `crates/dom-store/src/db.rs`
- `crates/dom-chain/tests/reorg_equivalence.rs`
- `crates/dom-chain/tests/corruption_detection.rs`
- `crates/dom-integration-tests/tests/replay_determinism.rs`

Root cause:

- `ChainState::connect_block` validates a block, builds the UTXO changeset, and
  calls `DomStore::commit_block`.
- Only after `commit_block` returns does `connect_block` compare
  `header.total_difficulty` with `self.tip_difficulty` and return
  `BestChain` or `SideChain`.
- `DomStore::commit_block` unconditionally writes:
  - block header by hash
  - block body by hash
  - `height_index[block_height] = block_hash`
  - `chain_tip = block_hash`
  - UTXO additions/removals
  - kernel index entries passed by caller

Confirmed consequence:

- A valid side-chain block can be persisted as `chain_tip` and can overwrite the
  height index for its height even when in-memory `ChainState` returns
  `ConnectResult::SideChain` and does not update `tip_hash`.
- This creates a split between in-memory best-chain state and persisted
  canonical pointers.

Replay implications:

- Two nodes that receive the same valid blocks in different orders can persist
  different `chain_tip` / `height_index` relations even when their in-memory
  best-chain choice agrees before shutdown.
- A replay from disk can resurrect the last persisted side-chain block as the
  node's tip because `ChainState::open` initializes from `store.get_chain_tip`.

Restart implications:

- Restart converts the persisted pointer relation into live `tip_hash`,
  `tip_height`, and `tip_difficulty`.
- If the persisted side-chain tip has lower/equal total difficulty than the
  pre-restart in-memory best tip, the node can restart onto a worse or stale
  branch.
- Existing corruption checks ensure pointer consistency, not canonical
  correctness. A side-chain tip with matching header/body/height index is
  internally consistent and therefore not detected as corruption.

Possible fork/divergence scenarios:

- Order-dependent restart divergence: node A sees best-chain block then
  side-chain block before shutdown; node B sees the same blocks in reverse.
  After restart, A may load the side-chain tip while B loads the best-chain tip.
- Mining divergence: a miner that restarts after persisting a side-chain block
  may mine on the wrong parent.
- IBD divergence: a node serving headers from `height_index` may advertise the
  side-chain path as canonical after restart.

Migration implications:

- Existing databases may already contain internally consistent but semantically
  wrong canonical pointers. A fix may need a recovery/audit command that walks
  stored headers, recomputes the best chain by total difficulty, and compares it
  against persisted `chain_tip` and `height_index`.
- Automatic repair would alter chain selection state and requires approval.

Affected invariants:

- `chain_tip` must identify the best known chain, not merely the most recently
  committed block.
- `height_index[h]` must map to the canonical block at height `h`.
- Replaying the same accepted block multiset in different arrival orders must
  yield the same restart tip.
- Restart state must be equivalent to pre-shutdown in-memory state.

Implemented minimal deterministic correction:

- Separate immutable block-body/header storage from canonical pointer updates.
- `DomStore::store_known_block` persists side-chain header/body bytes by hash
  only.
- `ChainState::connect_block` calls `commit_block` only when the block is both
  higher total difficulty and a direct extension of the current in-memory tip.
- Non-canonical blocks return `ConnectResult::SideChain` and are retained by
  hash without touching `chain_tip`, canonical `height_index`, UTXO state, or
  kernel state.

Compatibility impact:

- Serialization and wire compatibility are unchanged.
- Previously, a valid side-chain block could alter persisted canonical pointers.
  That behavior is intentionally removed.
- Existing stores that already contain side-chain blocks as canonical pointers
  are not auto-repaired by this correction. They still need an explicit audit or
  recovery command before mainnet.

Migration/recovery implications:

- No schema migration is required.
- Operators with pre-correction data may have internally consistent but
  semantically wrong canonical pointers. Recovery tooling should recompute the
  best chain by walking stored headers and compare it with `chain_tip` and
  `height_index`.
- Automatic repair remains a separate high-risk change because it mutates
  persisted chain-selection state.

Validated invariants:

- Known side blocks do not rewrite `chain_tip`.
- Known side blocks do not rewrite canonical `height_index`.
- Known side blocks do not mutate the canonical UTXO set.
- Duplicate known side blocks hit hash-level duplicate suppression.
- Alternating canonical and side arrivals reopen to the canonical chain.
- Delayed side-branch candidates remain non-canonical after restart until an
  explicit reorg engine promotes them.

Remaining correction candidate, not yet implemented:

- Add a deterministic chain-selection/reorg transaction that updates canonical
  pointers and UTXO state when a side branch genuinely becomes best.

Required tests before this hardening area can be called complete:

- Full reorg equivalence test comparing promoted branch state to fresh replay
  from fork point.
- Store audit/recovery test detecting pre-correction canonical pointer drift.
- IBD header-serving test proving post-restart locators follow the same
  canonical path as pre-restart memory.

## Finding B: Kernel Replay Index Exists But Is Not Wired

Classification: confirmed, consensus-critical.

Correction status: hardened in the current working tree.

Affected files:

- `crates/dom-chain/src/chain_state.rs`
- `crates/dom-store/src/db.rs`
- `crates/dom-consensus/src/transaction.rs`
- `crates/dom-consensus/src/lib.rs`
- `crates/dom-chain/tests/corruption_detection.rs`

Root cause:

- `DomStore::commit_block` accepts `kernel_excesses` and writes each
  `excess -> block_hash` into `kernel_index` using `NO_OVERWRITE`.
- The error path explicitly treats duplicate excess insertion as kernel replay.
- `ChainState::connect_block` currently passes `&[]` for `kernel_excesses`.
- Transaction structure validation checks duplicate input commitments and output
  commitments inside one transaction, but does not index or enforce historical
  kernel excess uniqueness.

Confirmed consequence:

- The persistent global kernel replay guard is dormant on the normal
  `connect_block` path.
- Historical duplicate kernel excesses are not detected by the store index
  because no excesses are inserted.

Likely consequence:

- A block containing a kernel excess already accepted in an earlier block may
  pass this specific global uniqueness guard. Whether it can fully pass all
  cryptographic and balance checks depends on the constructed transaction and
  UTXO availability, so exploitability requires a dedicated reproducer.

Replay implications:

- Wiring the index would make historical duplicate kernels reject at commit
  time or earlier.
- That changes validator/block validity behavior for any chain data that
  currently contains duplicate kernel excesses.

Restart implications:

- If existing stores lack kernel index entries, enabling enforcement without a
  migration could make duplicate detection depend on whether the node started
  from a fresh replay or an old partially indexed database.
- A migration/audit path must either rebuild the kernel index deterministically
  from canonical blocks or reject stores with missing/incomplete kernel index
  coverage.

Possible fork/divergence scenarios:

- Old node accepts a block with historical duplicate kernel excess; hardened
  node rejects it.
- Hardened node with rebuilt kernel index rejects a block that a hardened node
  with an old empty kernel index might accept, if migration is not mandatory and
  deterministic.

Migration implications:

- Existing databases need a kernel-index audit/rebuild story before enforcement.
- Rebuild must be canonical-chain-only unless side-chain kernel indexing is
  deliberately specified.

Affected invariants:

- A kernel excess must be globally unique over the accepted canonical history.
- Enforcement must be identical across fresh replay, restart from existing
  store, and IBD sync.
- Miner, validator, storage, and replay paths must agree on exactly which
  kernels are indexed.

Implemented minimal deterministic correction:

- `ChainState::connect_block` extracts the coinbase kernel excess and every
  transaction kernel excess from canonical direct-extension blocks and passes
  them to `DomStore::commit_block`.
- `DomStore::commit_block` already indexes those kernel excesses atomically
  with the block commit using `NO_OVERWRITE`.
- `ChainState::open` walks the canonical height index from height 1 through
  the persisted tip, decodes canonical block bodies, verifies the body header
  hashes back to the height-index hash, and calls `DomStore::ensure_kernel_indices`.
- `DomStore::ensure_kernel_indices` inserts missing legacy entries,
  accepts existing matching entries, and rejects any entry that points the same
  excess at another block.

Compatibility impact:

- Serialization and wire compatibility are unchanged.
- Fresh canonical commits now populate `kernel_index`; that is the intended
  activation of the existing storage invariant.
- Old stores with missing kernel index entries are repaired deterministically on
  reopen.
- Old stores with duplicate kernel excesses in canonical history now fail
  reopen instead of silently continuing. This is an intentional consensus
  safety stop, not a schema migration.

Migration/recovery implications:

- No database reset or schema migration is required for healthy old stores.
- Reindex is canonical-chain-only; side-chain known blocks remain header/body
  retention and do not populate canonical kernel state.
- If a store contains duplicate canonical kernel excesses, safe recovery is to
  stop and rebuild/resync from a non-corrupt canonical source. Auto-repair would
  require choosing which accepted block to remove and is therefore not
  attempted.

Validated invariants:

- New canonical commits atomically index kernel excesses with block persistence.
- Reopen fills missing legacy kernel index entries.
- Reopen is equivalent to fresh replay for kernel index coverage.
- Duplicate canonical kernel excesses are detected during legacy reindex.
- Side-chain known blocks do not populate canonical kernel state.

Remaining correction candidates:

- Add an operator-facing audit command that reports kernel index status without
  starting the node.
- Add end-to-end replay tests with real mined blocks when RandomX runtime is
  available.

Required tests before completion:

- End-to-end duplicate-kernel block rejection through the live block-acceptance
  path once a cheap consensus-valid fixture generator exists.
- Dedicated operator recovery/audit command tests.

## Finding C: Live IBD Does Not Use The Headers-First State Machine

Classification: confirmed, distributed-instability, consensus-critical if fixed.

Affected files:

- `crates/dom-node/src/node.rs`
- `crates/dom-chain/src/ibd.rs`
- `crates/dom-chain/tests/ibd_adversarial.rs`
- `crates/dom-integration-tests/tests/ibd.rs`

Root cause:

- `dom-chain::IbdState` models headers-first sync and has adversarial tests for
  continuity, replay, gaps, stale batches, and pending block draining.
- The live node `ibd_sync_round` sends `GetHeaders`, waits for one `Headers`
  message, computes hashes directly from peer-supplied header bytes, filters
  known hashes, and requests bodies.
- The live path does not call `IbdState::process_headers`.
- The live path does not call `ChainState::validate_header_only` before
  requesting block bodies.
- The live path relies on later `connect_block` validation after body download.

Confirmed consequence:

- A peer can make the node request block bodies for headers that have not gone
  through the documented headers-first state machine.
- Invalid, discontinuous, low-work, or adversarial header batches are not
  rejected at the header phase in the live path.

Likely consequence:

- Malicious peers can amplify bandwidth and block-deserialization work by
  supplying bogus header bytes that pass wire payload parsing but fail only
  after body download or block connection.

Replay implications:

- Moving validation earlier should not change the validity of well-formed
  canonical blocks, but it changes when and why peer data is rejected.
- If early header validation checks parent continuity, MTP, PoW seed, or total
  difficulty differently from `connect_block`, it can introduce miner/validator
  drift.

Restart implications:

- Header-first validation must use the same stored canonical view before and
  after restart. If `height_index` is already corrupted by Finding A, IBD
  validation and locator construction can inherit the wrong canonical path.

Possible fork/divergence scenarios:

- A strict node refuses to request bodies for a header sequence that a current
  node would download and later accept due to different validation context.
- A node with stale/wrong persisted canonical pointers may validate IBD headers
  against a different parent chain after restart.

Migration implications:

- No database migration is necessarily required for early validation alone.
- If the fix depends on canonical pointer correction, it must be sequenced after
  the side-chain persistence fix or explicitly guarded.

Affected invariants:

- Header validation used in IBD must be semantically identical to header
  validation used during full block connection.
- Header hash ordering requested in `GetBlockData` must correspond to validated
  header order.
- A peer must not be able to cause unbounded body downloads from invalid header
  batches.

Minimal deterministic correction candidates, not approved:

- Route live IBD through `IbdState` and `ChainState::validate_header_only`.
- Verify header continuity and parent linkage before body requests.
- Keep body `connect_block` as the final authority and assert equivalence
  between header-prechecked and direct validation paths.

Required tests before completion:

- Live IBD rejects gap/backwards/replayed headers before body request.
- Header-prechecked accepted sequence matches direct `connect_block` replay.
- Restarted node builds the same locator and requests the same body hashes as a
  non-restarted node.
- Malformed header payload fuzz seeds do not trigger body requests.

## Finding D: Future-Block Queue Is Partially Wired

Classification: confirmed, distributed-instability, consensus-adjacent.

Affected files:

- `crates/dom-node/src/future_block_queue.rs`
- `crates/dom-node/src/node.rs`

Root cause:

- `DomNode` owns a `future_block_queue` and starts a periodic drain loop.
- The relay `Command::Block` path constructs a `DeferredBlock` when timestamp
  validation returns `Defer`, but the queue is not in scope there and the code
  logs "queue not yet wired" instead of enqueuing.
- The deferred `block_hash` currently uses height/timestamp bytes, not the real
  block hash.

Confirmed consequence:

- Future-timestamp soft-buffered relayed blocks are dropped instead of queued.
- The drain loop has no live entries from the relay path to reprocess.

Replay implications:

- Fixing this changes arrival-order behavior for blocks in the soft timestamp
  window. That may be desirable but must be treated as replay behavior until the
  equivalence tests are in place.

Restart implications:

- The current queue is in-memory only. A restart forgets deferred blocks.
- Persisting the queue would alter replay/restart semantics and needs separate
  approval.

Possible fork/divergence scenarios:

- Node A receives a slightly future valid block and drops it; node B receives
  the same block later and accepts it. This can cause temporary divergence and
  extra IBD/relay churn.
- If queueing is added without deterministic hash keys and duplicate handling,
  duplicate relays may replace or amplify deferred work inconsistently.

Migration implications:

- None for an in-memory-only queue.
- Persistent deferred-block storage would require a schema and replay policy.

Affected invariants:

- Future-block deferral must not weaken the hard timestamp consensus rule.
- Reprocessing must be deterministic given the same clock input.
- Duplicate future blocks must not grow memory or trigger repeated validation
  amplification.

Minimal deterministic correction candidates, not approved:

- Pass `future_block_queue` into the message loop and enqueue using the real
  block hash.
- Keep the queue in-memory only.
- Add deterministic duplicate suppression and bounded revalidation tests.

Required tests before completion:

- Deferred block is queued once, later drained, and accepted/rejected by the
  same `connect_block` path as immediate relay.
- Duplicate deferred block does not increase queue size.
- Restart equivalence is explicitly documented as "deferred relay cache is
  volatile" unless persistence is approved.

## Current Approval Queue

Pending approval:

- Canonical side-chain persistence correction.
- Kernel replay index enforcement and migration/audit path.
- Live IBD headers-first validation closure.
- Future-block queue live reprocessing if treated as replay behavior.
- Any parser strictness changes that reject bytes previously accepted.

Safe next work:

- Add tests that document current queue duplicate behavior.
- Add fuzz harnesses for peer-reachable parsers without changing acceptance.
- Add analysis-only corruption/replay test scaffolding that is ignored or
  explicitly marked as a current-behavior reproducer.
