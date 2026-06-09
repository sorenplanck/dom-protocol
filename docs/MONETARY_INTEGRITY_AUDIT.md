# DOM Monetary Integrity Audit

Status: Phase 0 audit, documentation-only
Scope: emission, supply ceiling, coinbase construction, coinbase validation, UTXO maturity
Date: 2026-06-09
Change class: Non-executable documentation

## 1. Executive Summary

This audit maps the current DOM monetary implementation for issuance, supply,
coinbase value binding, fee inclusion, and coinbase maturity. It does not change
consensus, validation, RandomX, difficulty, block format, node behavior, wallet
behavior, RPC, or tests.

The implementation has a clear monetary control path:

- `dom_core::block_reward` returns the deterministic subsidy for a height.
- `CoinbaseKernel::validate_explicit_value` requires coinbase value to equal
  base subsidy plus non-coinbase transaction fees.
- `CoinbaseTransaction::validate` verifies zero coinbase offset, explicit value,
  coinbase range proof, and coinbase kernel signature.
- `validate_block_transactions` sums actual non-coinbase fees and validates the
  coinbase against those fees.
- `validate_block` also verifies the aggregate block balance equation using the
  base reward.
- `ChainState::connect_block` routes accepted blocks through full block
  validation before UTXO mutation and persistence.
- UTXO metadata records coinbase outputs and enforces network-specific maturity
  on spend.

No functional code was changed in this phase.

## 2. Scope Reviewed

Reviewed implementation files:

- `crates/dom-core/src/constants.rs`
- `crates/dom-core/src/types.rs`
- `crates/dom-consensus/src/transaction.rs`
- `crates/dom-consensus/src/lib.rs`
- `crates/dom-consensus/src/block_full.rs`
- `crates/dom-chain/src/chain_state.rs`
- `crates/dom-store/src/utxo.rs`
- `crates/dom-node/src/miner.rs`

Reviewed monetary documentation:

- `docs/DOM_RFC_0008_Balance_Coinbase_Fee_Offset.md`
- `docs/MONETARY_ALIGNMENT_REVIEW.md`
- `docs/MONETARY_CONSTITUTION.md`
- `docs/MONETARY_INTEGRITY_PROOFS.md`

Mandatory audit documents were also read before this review. The required path
`audit/00_MASTER_INDEX.md` was initially not present; the repository contained
`audit/00_MASTER_INDEX` without the `.md` extension. This was closed by adding
`audit/00_MASTER_INDEX.md` as a compatibility path while preserving the original
file.

## 3. Methodology

This was a static, documentation-only audit pass. The review traced monetary
state from constants to block reward calculation, coinbase construction,
coinbase validation, block validation, UTXO mutation, and coinbase spend
maturity. No executable regression tests were added because this phase is
explicitly limited to audit and RFC documentation.

## 4. Monetary Control Map

| Area | File | Function or item | Current role |
|---|---|---|---|
| Supply unit | `crates/dom-core/src/constants.rs` | `COIN_UNIT` | Defines `1 DOM = 100_000_000` noms. |
| Initial reward | `crates/dom-core/src/constants.rs` | `INITIAL_BLOCK_REWARD` | Defines initial subsidy as 33 DOM. |
| Epoch interval | `crates/dom-core/src/constants.rs` | `HALVING_INTERVAL` | Defines reward epoch length as 330,000 blocks. |
| Reward schedule | `crates/dom-core/src/constants.rs` | `BLOCK_REWARD_TABLE` | Defines deterministic per-epoch rewards. |
| Supply ceiling | `crates/dom-core/src/constants.rs` | `MAX_SUPPLY_NOMS` | Computes maximum possible subsidy from reward table. |
| Height epoch | `crates/dom-core/src/types.rs` | `BlockHeight::halving_epoch` | Maps height to reward epoch. |
| Subsidy lookup | `crates/dom-core/src/types.rs` | `block_reward` | Returns reward table value or zero after active epochs. |
| Amount ceiling | `crates/dom-core/src/types.rs` | `Amount::from_noms` | Rejects amounts above `MAX_SUPPLY_NOMS`. |
| Coinbase value binding | `crates/dom-consensus/src/transaction.rs` | `CoinbaseKernel::validate_explicit_value` | Requires `explicit_value == reward + fees`. |
| Coinbase validation | `crates/dom-consensus/src/transaction.rs` | `CoinbaseTransaction::validate` | Checks zero offset, explicit value, range proof, and signature. |
| Block fee sum | `crates/dom-consensus/src/block_full.rs` | `Block::total_fees` | Sums non-coinbase transaction fees with overflow checks. |
| Block validation | `crates/dom-consensus/src/lib.rs` | `validate_block_transactions` | Validates transactions, computes actual fees, validates coinbase. |
| Aggregate balance | `crates/dom-consensus/src/block_full.rs` | `validate_block` | Verifies full block balance equation using base reward. |
| Block connection | `crates/dom-chain/src/chain_state.rs` | `ChainState::connect_block` | Validates header, PoW, difficulty, block body, then commits UTXO changes. |
| UTXO tagging | `crates/dom-chain/src/chain_state.rs` | `build_utxo_changeset` | Marks coinbase UTXOs with `is_coinbase: true`. |
| Direct maturity | `crates/dom-chain/src/chain_state.rs` | `validate_direct_extension_inputs` | Rejects immature coinbase spends on direct extension. |
| Reorg maturity | `crates/dom-chain/src/chain_state.rs` | `apply_connect` | Rejects immature coinbase spends during reorg promotion. |
| Stored UTXO metadata | `crates/dom-store/src/utxo.rs` | `UtxoEntry` | Stores creation height, coinbase flag, and range proof bytes. |
| Maturity helper | `crates/dom-store/src/utxo.rs` | `UtxoEntry::is_mature_for` | Applies network-specific coinbase maturity threshold. |
| Miner coinbase | `crates/dom-node/src/miner.rs` | `build_coinbase_with_blinding` | Builds coinbase with `reward + fees`, proof, excess, and signature. |
| Mempool fee inclusion | `crates/dom-node/src/miner.rs` | `mine_one_block` coinbase branch | Sums selected transaction fees before building coinbase. |

## 5. Findings Summary

| ID | Severity | Area | Title | Status |
|---|---|---|---|---|
| DOM-MIL-001 | High | Documentation | RFC-0008 reward formula text conflicts with current implementation | Resolved by RFC-0008 update |
| DOM-MIL-002 | Medium | Auditability | No public, single-source monetary integrity transcript exists | Resolved by transcript spec |
| DOM-MIL-003 | Medium | Auditability | No documented deterministic supply replay procedure exists | Resolved by replay procedure |
| DOM-MIL-004 | Low | Documentation | `audit/00_MASTER_INDEX.md` path mismatch | Resolved by compatibility file |
| DOM-MIL-005 | Informational | Consensus | Current implementation has explicit coinbase value enforcement | Observed |

## 6. Detailed Findings

### DOM-MIL-001 - RFC-0008 reward formula text conflicts with current implementation

Severity: High
Area: Documentation
Status: Resolved by RFC-0008 update

Affected files:

- `docs/DOM_RFC_0008_Balance_Coinbase_Fee_Offset.md`
- `crates/dom-core/src/constants.rs`
- `crates/dom-core/src/types.rs`

Description:

RFC-0008 previously described a reward formula that diverged from the current
implementation. The implementation uses `BLOCK_REWARD_TABLE`, where each epoch
is derived by integer arithmetic `reward(n) = (reward(n-1) * 67) / 100`.
`block_reward` indexes that table and returns zero after `HALVING_EPOCHS`.

Impact:

A future implementer following the RFC text could produce a consensus-
incompatible reward schedule and accept or mine blocks with incorrect coinbase
values.

Exploitability:

This is not directly exploitable against the current implementation unless an
alternate client, audit tool, or migration follows the stale RFC formula. The
risk is cross-implementation divergence and incorrect external verification.

Evidence:

- `docs/DOM_RFC_0008_Balance_Coinbase_Fee_Offset.md` has been updated to make
  `BLOCK_REWARD_TABLE` the normative current reward schedule.
- `crates/dom-core/src/constants.rs` defines the active table and supply ceiling.
- `crates/dom-core/src/types.rs` implements `block_reward` as table lookup.

Recommended fix:

No further Phase 1 documentation fix is required. Phase 2 implementations MUST
use `BLOCK_REWARD_TABLE` and `dom_core::block_reward(height)` as the audit
source for the reward schedule.

Validation commands:

```bash
cargo test -p dom-core reward_table_is_deterministic supply_matches_expected_value
```

### DOM-MIL-002 - No public, single-source monetary integrity transcript exists

Severity: Medium
Area: Auditability
Status: Resolved by transcript spec

Affected files:

- `crates/dom-core/src/constants.rs`
- `crates/dom-core/src/types.rs`
- `crates/dom-consensus/src/transaction.rs`
- `crates/dom-consensus/src/block_full.rs`
- `crates/dom-chain/src/chain_state.rs`

Description:

The monetary rules are enforced through the implementation. This gap was closed
at the specification level by defining the single public transcript in
`docs/MONETARY_INTEGRITY_TRANSCRIPT_SPEC.md`.

Impact:

External auditors now have a documented transcript schema to use for future
offline/read-only verification tooling.

Exploitability:

This does not create an inflation path by itself. It increases the chance that
supply divergence, stale documentation, or implementation drift is detected late
by independent reviewers.

Evidence:

- Current enforcement is distributed across reward constants, coinbase
  validation, aggregate block balance, and UTXO mutation.
- `docs/MONETARY_INTEGRITY_TRANSCRIPT_SPEC.md` defines the concrete public
  transcript schema, canonical JSON ordering, privacy boundary, and hash rule.

Recommended fix:

Phase 2 should implement the transcript spec as read-only/offline tooling. It
must not affect consensus, block acceptance, mining, wallet state, or RPC.

Validation commands:

```bash
cargo test --workspace
cargo fmt --check
```

### DOM-MIL-003 - No documented deterministic supply replay procedure exists

Severity: Medium
Area: Auditability
Status: Resolved by replay procedure

Affected files:

- `crates/dom-chain/src/chain_state.rs`
- `crates/dom-store/src/utxo.rs`
- `crates/dom-consensus/src/block_full.rs`

Description:

The chain state contains deterministic replay and canonical UTXO reconstruction
logic. This gap was closed at the procedure level by
`docs/MONETARY_SUPPLY_REPLAY_PROCEDURE.md`, which defines how to derive issued
subsidy, collected fees, coinbase status, UTXO counts, and transcript output
from canonical history.

Impact:

Supply review now has a published deterministic procedure for future
offline/read-only audit tooling.

Exploitability:

Low as a direct attack. Medium as an operational risk because independent
auditors could use inconsistent replay assumptions.

Evidence:

- `ChainState::connect_block` validates blocks before state mutation.
- `build_utxo_changeset` tags coinbase outputs.
- `UtxoEntry` stores the coinbase flag and height.
- `docs/MONETARY_SUPPLY_REPLAY_PROCEDURE.md` defines a canonical replay
  procedure and points to the transcript output.

Recommended fix:

Phase 2 should implement this replay procedure with fixed fields, stable
ordering, and golden vectors.

Validation commands:

```bash
cargo test -p dom-chain
cargo test -p dom-store
```

### DOM-MIL-004 - `audit/00_MASTER_INDEX.md` path mismatch

Severity: Low
Area: Audit process
Status: Resolved by compatibility file

Affected files:

- `AGENTS.md`
- `audit/00_MASTER_INDEX`

Description:

The operational instructions require `audit/00_MASTER_INDEX.md`, while the
repository originally had `audit/00_MASTER_INDEX` without `.md`. This was closed
by adding `audit/00_MASTER_INDEX.md` as a compatibility file and preserving the
original path.

Impact:

Automated auditors can now satisfy either path.

Exploitability:

Not security-exploitable in protocol terms. It is an audit-process reliability
issue.

Evidence:

`rg --files audit` now lists both `audit/00_MASTER_INDEX` and
`audit/00_MASTER_INDEX.md`.

Recommended fix:

No further Phase 1 action is required. Future updates should keep both files
aligned or formally retire one path with explicit tooling review.

Validation commands:

```bash
rg --files audit
```

### DOM-MIL-005 - Current implementation has explicit coinbase value enforcement

Severity: Informational
Area: Consensus
Status: Observed

Affected files:

- `crates/dom-consensus/src/transaction.rs`
- `crates/dom-consensus/src/lib.rs`
- `crates/dom-consensus/src/block_full.rs`
- `crates/dom-node/src/miner.rs`

Description:

The current implementation explicitly binds coinbase value to
`block_reward(height) + actual_total_fees`, checks overflow, validates the
coinbase range proof, validates the coinbase kernel signature, and verifies an
aggregate block balance equation.

Impact:

This is the expected inflation-prevention design. It should remain protected by
negative tests and future public replay tooling.

Exploitability:

No exploit is asserted for this item.

Evidence:

- `CoinbaseKernel::validate_explicit_value`
- `CoinbaseTransaction::validate`
- `validate_block_transactions`
- `validate_block`
- `build_coinbase_with_blinding`

Recommended fix:

No Phase 0/1 code change. Phase 2 should add non-invasive audit tooling and
negative tests around any new verification surface.

Validation commands:

```bash
cargo test -p dom-consensus
cargo test -p dom-node
```

## 7. Consensus Impact Assessment

This audit made no consensus changes. It did not alter monetary constants,
coinbase validation, block validation, transaction validation, difficulty, PoW,
block format, serialization, or UTXO mutation.

## 8. Cryptography Impact Assessment

This audit made no cryptographic changes. It reviewed coinbase range proof and
Schnorr signature validation paths only as static evidence.

## 9. Mempool/Reorg/Double-Spend Assessment

This audit reviewed fee summing from selected mempool transactions into miner
coinbase construction and reviewed direct-extension and reorg coinbase maturity
checks. It did not modify mempool, reorg, or double-spend behavior.

## 10. Wallet Safety Assessment

Wallet implementation was not changed. Miner behavior currently uses wallet
coinbase construction when a wallet is configured and refuses public-network
mining without a wallet to avoid burning rewards.

## 11. P2P/DoS Assessment

P2P behavior was not changed. Phase 2 monetary verification should remain
offline/read-only unless explicitly authorized otherwise.

## 12. Validation Evidence

Commands run during Phase 0:

```bash
rg --files audit
rg -n "coinbase|emission|supply|subsidy|reward|MONETARY|MAX_SUPPLY|BLOCK_REWARD|maturity|fee" crates docs Cargo.toml README.md
git status --short
```

Documentation-only validation required after creating this report:

```bash
git diff --check
git status --short
```

No cargo validation was required for Phase 0 because no executable code, tests,
consensus files, validation files, RandomX code, difficulty code, node behavior,
wallet behavior, RPC, or block format were changed.

## 13. Files Changed

Documentation-only files created in Phase 0/1:

- `docs/MONETARY_INTEGRITY_AUDIT.md`
- `docs/DOM_RFC_0015_Monetary_Integrity_Layer.md`
- `docs/MONETARY_INTEGRITY_TRANSCRIPT_SPEC.md`
- `docs/MONETARY_SUPPLY_REPLAY_PROCEDURE.md`
- `audit/00_MASTER_INDEX.md`

Documentation-only files updated in closure pass:

- `audit/BOOTSTRAP_READING_REPORT.md`
- `audit/DOM_AUDIT_REPORT.md`
- `audit/FULL_PROTOCOL_AUDIT_REPORT.md`
- `docs/DOM_RFC_0008_Balance_Coinbase_Fee_Offset.md`
- `docs/DOM_RFC_0015_Monetary_Integrity_Layer.md`
- `docs/MONETARY_INTEGRITY_AUDIT.md`

## 14. Forbidden File Compliance

No forbidden consensus, cryptography, genesis, difficulty, validation,
persistence schema, wallet, release, or deployment files were modified.

## 15. Closure Verification

The Phase 0/1 lacunas were closed without changing functional code:

- DOM-MIL-001 was closed by updating RFC-0008 to align with
  `BLOCK_REWARD_TABLE`, integer `*67/100` table derivation, table lookup through
  `block_reward(height)`, and zero reward after `HALVING_EPOCHS`.
- DOM-MIL-002 was closed by creating
  `docs/MONETARY_INTEGRITY_TRANSCRIPT_SPEC.md`.
- DOM-MIL-003 was closed by creating
  `docs/MONETARY_SUPPLY_REPLAY_PROCEDURE.md`.
- DOM-MIL-004 was closed by creating `audit/00_MASTER_INDEX.md` while preserving
  `audit/00_MASTER_INDEX`.

No consensus, validation, RandomX, difficulty, block format, serialization,
node behavior, wallet behavior, RPC, explorer, metrics, or executable tests
were changed.

## 16. Remaining Risks

Primary remaining risks:

- Public monetary audit tooling is specified but not implemented.
- The deterministic replay procedure is specified but not implemented.
- No Phase 2 negative tests exist yet for future offline audit tooling.

## 17. Final Recommendation

Ready for a documentation-only commit. Future Phase 2 implementation should be
limited to read-only, offline verification tooling plus non-consensus tests
unless explicitly authorized otherwise.
