# DOM Protocol Security Audit Report - Phase 1.3 / 1.4

Date: 2026-06-16  
Auditor: Independent security review via Codex  
Scope: Phase 1.3 Monetary Supply and Phase 1.4 Transaction Balance only

## 1. Executive Summary

This audit reviewed DOM Protocol's monetary issuance, fee accounting, coinbase validation, transaction balance equation, aggregate block balance equation, cut-through handling, duplicate detection, and relevant UTXO integration paths.

Overall assessment: the main serialized block/transaction path enforces reward + fee coinbase accounting, checked fee summation, transaction range proofs, kernel signatures, transaction balance, aggregate block balance, duplicate input/output checks, and canonical block-level cut-through. One confirmed validation gap was found: `validate_block` can accept an in-memory `Block` whose coinbase kernel uses a non-coinbase feature byte, because the feature check exists in `CoinbaseKernel::deserialize` but not in `CoinbaseTransaction::validate`.

No repository files were modified. One temporary regression test was written, run, and removed.

## 2. Scope Reviewed

Crates and files inspected:

- `crates/dom-core/src/constants.rs`
- `crates/dom-core/src/types.rs`
- `crates/dom-consensus/src/transaction.rs`
- `crates/dom-consensus/src/block_full.rs`
- `crates/dom-consensus/src/cutthrough.rs`
- `crates/dom-consensus/src/lib.rs`
- `crates/dom-consensus/tests/adversarial_block_validation.rs`
- `crates/dom-chain/src/chain_state.rs`
- `crates/dom-store/src/db.rs`
- `crates/dom-store/src/utxo.rs`
- `crates/dom-crypto/src/pedersen.rs`
- `crates/dom-crypto/src/bulletproof.rs`
- `crates/dom-tx/src/lib.rs`
- `crates/dom-mempool/src/lib.rs`
- `crates/dom-node/src/miner.rs`
- monetary/spec references in `WHITEPAPER.md`, `README.md`, and `docs/DOM_RFC_0008_Balance_Coinbase_Fee_Offset.md`

## 3. Methodology

- Static review of all code paths relevant to emission, fees, coinbase, transaction balance, aggregate block balance, cut-through, duplicate detection, and contextual UTXO spend checks.
- Validation-path tracing from block construction/deserialization through `validate_block`, `connect_block`, UTXO mutation, side-chain retention, and reorg promotion.
- Negative/adversarial test review for aggregate balance, reward/fee equation, cut-through, invalid kernel excess, and UTXO input validation.
- Temporary proof-of-bug test for malformed in-memory coinbase kernel feature acceptance.
- Targeted test execution and baseline command attempts.

Limitations:

- P2P/wire decoding beyond the monetary/balance entry points was not audited except where it affects whether malformed coinbase features can reach `validate_block`.
- Full `cargo test --workspace` was started and many suites passed, but the final summary was not captured before the session ended; targeted scope tests completed.

## 4. Findings Summary

| ID | Severity | Area | Title | Status |
|----|----------|------|-------|--------|
| DOM-1.3-001 | Medium | Consensus | Coinbase feature byte is enforced at deserialization but not by block validation | CONFIRMED |
| DOM-1.3-OBS-001 | Informational | Monetary Policy | "Halving" terminology conflicts with the implemented 67% retention schedule | CONFIRMED OBSERVATION |

## 5. Detailed Findings

### DOM-1.3-001 - Coinbase feature byte is enforced at deserialization but not by block validation

Severity: Medium  
Area: Consensus / Coinbase validation  
Status: CONFIRMED

#### Affected Files

- `crates/dom-consensus/src/transaction.rs`
- `crates/dom-consensus/src/block_full.rs`

#### Invariant Violated

- Block Validity: Coinbase count and placement must obey protocol rules.
- Monetary Safety: Coinbase outputs must obey deterministic emission rules.
- Cryptographic Assumptions: Kernel signatures must bind to the correct transaction/kernel message.

#### Description

`CoinbaseKernel` documents `features` as always `KERNEL_FEAT_COINBASE = 0x01` at `crates/dom-consensus/src/transaction.rs:119-121`. `CoinbaseKernel::deserialize` rejects any other feature byte at `crates/dom-consensus/src/transaction.rs:162-169`.

However, `CoinbaseTransaction::validate` does not independently check `self.kernel.features == KERNEL_FEAT_COINBASE` before validating explicit value, range proof, and signature at `crates/dom-consensus/src/transaction.rs:363-394`. Its signature message includes `self.kernel.features` at `crates/dom-consensus/src/transaction.rs:404-408`, so an in-memory block can be constructed with `KERNEL_FEAT_PLAIN`, signed consistently, and accepted by `validate_block`.

`validate_block` calls `validate_block_transactions` and aggregate balance validation at `crates/dom-consensus/src/block_full.rs:122-178`, but it never adds a coinbase feature check.

#### Impact

The canonical wire deserialization path rejects this malformed coinbase, so immediate remote exploitability through ordinary serialized P2P blocks appears constrained. The risk is still consensus-relevant because the public validation API accepts an invalid `Block` object if any local construction, miner, RPC, test harness, IBD transformation, or future refactor bypasses `CoinbaseKernel::deserialize`.

This creates a split between "bytes accepted by deserialize" and "objects accepted by validate_block", which is unsafe for consensus code. Validation should be complete and construction-path independent.

#### Exploitability

Medium in current code: ordinary `Block::from_bytes` rejects the malformed feature. Exploitability rises to High if any block ingress path constructs `Block` structs directly from non-canonical data, exposes block submission as structured JSON, or reuses `validate_block` for internally generated blocks without deserialization.

#### Evidence

Temporary regression test result:

```text
Running tests/temp_coinbase_feature.rs
test validate_block_accepts_coinbase_kernel_with_plain_feature_when_constructed_in_memory ... ok
```

The test constructed a coinbase with `kernel.features = KERNEL_FEAT_PLAIN`, recomputed the coinbase signature over that feature byte, computed PMMR roots, and called `validate_block`. Current behavior accepted the block.

#### Reproduction

Regression test that fails today if written with the desired assertion:

```rust
#[test]
fn validate_block_rejects_coinbase_kernel_with_plain_feature() {
    use dom_consensus::block::{BlockHeader, ProofOfWork};
    use dom_consensus::{
        compute_block_pmmr_roots, validate_block, Block, CoinbaseKernel,
        CoinbaseTransaction, TransactionOutput, ValidationContext,
    };
    use dom_core::{
        BlockHeight, Hash256, Timestamp, KERNEL_FEAT_PLAIN, PROTOCOL_VERSION,
        TAG_KERNEL_MSG_COINBASE,
    };
    use dom_crypto::{
        bulletproof, hash::blake2b_256_tagged, keys::SecretKey,
        pedersen::{BlindingFactor, Commitment}, schnorr_sign,
    };
    use dom_pow::CompactTarget;
    use primitive_types::U256;

    let chain_id = [0x11; 32];
    let height = BlockHeight(1);
    let explicit_value = dom_core::block_reward(height).noms();
    let mut blind = [0u8; 32];
    blind[31] = 90;
    let blinding = BlindingFactor::from_bytes(blind).unwrap();
    let output_commitment = Commitment::commit(explicit_value, &blinding);
    let (proof, _) = bulletproof::prove(explicit_value, &blinding).unwrap();
    let excess = Commitment::commit(0, &blinding);

    let msg = {
        let mut data = Vec::with_capacity(9);
        data.push(KERNEL_FEAT_PLAIN);
        data.extend_from_slice(&explicit_value.to_le_bytes());
        blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data)
    };
    let secret = SecretKey::from_bytes(blinding.as_bytes()).unwrap();
    let sig = schnorr_sign(&secret, msg.as_bytes(), &chain_id).unwrap();

    let coinbase = CoinbaseTransaction {
        output: TransactionOutput {
            commitment: output_commitment,
            proof: proof.bytes,
        },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_PLAIN,
            explicit_value,
            excess,
            excess_signature: sig.to_bytes(),
        },
        offset: [0u8; 32],
    };
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, &[]).unwrap();
    let block = Block {
        header: BlockHeader {
            version: PROTOCOL_VERSION,
            height,
            prev_hash: Hash256::from_bytes([0x55; 32]),
            timestamp: Timestamp(1_704_067_260),
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0x1f00_ffff),
            total_difficulty: U256::from(2u64),
            pow: ProofOfWork {
                nonce: 7,
                randomx_hash: Hash256::ZERO,
            },
        },
        coinbase,
        transactions: vec![],
    };
    let ctx = ValidationContext {
        current_height: height,
        chain_id,
        now: Timestamp(u64::MAX),
    };

    let err = validate_block(&block, &ctx)
        .expect_err("coinbase kernel with non-coinbase feature must reject");
    assert!(err.to_string().contains("coinbase"));
}
```

#### Recommended Fix

Add an explicit check at the start of `CoinbaseTransaction::validate`:

```rust
if self.kernel.features != KERNEL_FEAT_COINBASE {
    return Err(DomError::Invalid(format!(
        "coinbase kernel features must be 0x01, got 0x{:02x}",
        self.kernel.features
    )));
}
```

Keep the existing `CoinbaseKernel::deserialize` check as defense in depth. Add the regression test above under `crates/dom-consensus` or equivalent.

#### Validation Required

- `cargo test -p dom-consensus validate_block_rejects_coinbase_kernel_with_plain_feature`
- `cargo test -p dom-consensus`
- `cargo test -p dom-chain --test aggregate_balance_adversarial`
- `cargo test -p dom-chain --test block_validation_ingress_adversarial`
- `cargo clippy --workspace --all-targets -- -D warnings`

### DOM-1.3-OBS-001 - "Halving" terminology conflicts with the implemented 67% retention schedule

Severity: Informational  
Area: Monetary Policy / Documentation  
Status: CONFIRMED OBSERVATION

#### Affected Files

- `README.md`
- `WHITEPAPER.md`
- `docs/DOM_RFC_0008_Balance_Coinbase_Fee_Offset.md`
- `crates/dom-core/src/constants.rs`

#### Invariant Violated

No consensus invariant violation was confirmed. The implementation is internally consistent with the whitepaper and RFC-0008.

#### Description

The user-provided scope describes "halving every 330,000 blocks". The repository's active implementation uses a 67% retention schedule:

- `BLOCK_REWARD_TABLE` is derived as `reward(n) = (reward(n-1) * 67) / 100` at `crates/dom-core/src/constants.rs:99-164`.
- `MAX_SUPPLY_NOMS` is computed from that table at `crates/dom-core/src/constants.rs:166-177`.
- Tests pin the exact total `3_299_999_976_900_000` noms at `crates/dom-core/src/constants.rs:752-755`.
- RFC-0008 says `BLOCK_REWARD_TABLE` is normative and forbids alternate formulas when they diverge at `docs/DOM_RFC_0008_Balance_Coinbase_Fee_Offset.md:195-206`.

This is consistent with `WHITEPAPER.md`, which explicitly says the schedule is not a strict halving. It conflicts with `README.md` wording that says "Halves every 330,000 blocks."

#### Impact

Documentation ambiguity around monetary policy is dangerous pre-mainnet because operators, auditors, and genesis witnesses may believe the economic rule is 50% halving when the consensus rule is 67% retention. This does not currently create inflation relative to the implemented RFC, but it can cause launch-signoff errors.

#### Exploitability

Not directly exploitable in consensus. Operational risk only.

#### Evidence

The implementation computes:

```text
MAX_SUPPLY_NOMS = 3,299,999,976,900,000
MAX_SUPPLY_DOM  = 32,999,999.769
```

A strict 50% halving every 330,000 blocks from 33 DOM would produce materially less total supply, about 21,779,999.9736 DOM under the same integer-floor approach.

#### Recommended Fix

Before mainnet ceremony, replace ambiguous "halving" language in high-level launch docs with "reward epoch" or "67% retention epoch", or explicitly state "not a strict 50% halving" wherever the term is used.

#### Validation Required

- `cargo test -p dom-core reward_table_is_deterministic supply_matches_expected_value`
- Human review of launch-facing monetary documentation.

## 6. Consensus Impact Assessment

Consensus validation for serialized blocks is strong in the reviewed monetary/balance paths: transaction structure, non-coinbase kernel feature restrictions, range proofs, Schnorr signatures, fee summation, transaction balance, aggregate block balance, duplicate block inputs/outputs, canonical cut-through, UTXO existence, maturity, and kernel replay defenses are present.

The confirmed issue is a validation completeness gap for in-memory coinbase objects. It should be fixed before mainnet because consensus validators should reject invalid objects independently of the construction/deserialization path.

## 7. Cryptography Impact Assessment

Reviewed cryptographic enforcement in scope:

- Output range proofs are verified for standard transaction outputs and coinbase outputs.
- Transaction kernel signatures are checked over feature, fee, and lock height.
- Coinbase signatures are checked over feature and explicit value using the coinbase domain tag.
- Pedersen balance equations include fee and offset for transactions, and base reward plus aggregate offset for blocks.

The confirmed finding arises because the coinbase signature binds the wrong feature byte if the in-memory object is malformed. The signature check itself works; the missing rule is that coinbase feature must equal `KERNEL_FEAT_COINBASE`.

## 8. Mempool/Reorg/Double-Spend Assessment

Reviewed only as needed for Phase 1.4:

- Direct extensions validate referenced inputs against the canonical UTXO set.
- Reorg promotion revalidates candidate blocks and applies branch UTXO checks with an overlay.
- Duplicate inputs across a block are rejected before state mutation.
- Same-block spends are rejected as block-level cut-through violations.
- Mempool admission uses full transaction validation and chain-view input checks in the production path.

No confirmed double-spend or cut-through bug was found in this scope.

## 9. Wallet Safety Assessment

Wallet internals were not broadly audited in this phase. Limited review of transaction construction found checked `amount + fee`, zero-value output rejection in `SpendBuilder`, and wallet/miner coinbase construction using `reward + fees`.

## 10. P2P/DoS Assessment

P2P was outside scope. Relevant note: ordinary serialized P2P block decoding appears to reject malformed coinbase features through `CoinbaseKernel::deserialize`, which limits immediate remote exploitability of DOM-1.3-001.

## 11. Validation Evidence

Commands run:

```bash
cargo test -p dom-core -- --nocapture
cargo test -p dom-consensus -- --nocapture
cargo test -p dom-chain --test aggregate_balance_adversarial -- --nocapture
cargo test -p dom-chain --test same_block_spend_cutthrough -- --nocapture
cargo test -p dom-chain --test block_validation_ingress_adversarial -- --nocapture
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
rg "unwrap\\(|expect\\(|panic!\\(|todo!\\(|unimplemented!\\(" crates/dom-core crates/dom-consensus crates/dom-chain crates/dom-crypto crates/dom-tx crates/dom-mempool crates/dom-node/src/miner.rs
rg "bypass|skip|insecure|debug|test_only|allow_invalid|disable_validation" crates/dom-core crates/dom-consensus crates/dom-chain crates/dom-crypto crates/dom-tx crates/dom-mempool crates/dom-node/src/miner.rs
rg "unsafe" crates/dom-core crates/dom-consensus crates/dom-chain crates/dom-crypto crates/dom-tx crates/dom-mempool crates/dom-node/src/miner.rs
git status --short
git diff --stat
git diff --check
git log --oneline -n 10
```

Results:

```text
cargo test -p dom-core -- --nocapture
PASS: 32 tests passed.

cargo test -p dom-consensus -- --nocapture
PASS: 54 unit tests + 6 adversarial tests passed.

cargo test -p dom-chain --test aggregate_balance_adversarial -- --nocapture
PASS: 3 tests passed.

cargo test -p dom-chain --test same_block_spend_cutthrough -- --nocapture
PASS: 3 tests passed.

cargo test -p dom-chain --test block_validation_ingress_adversarial -- --nocapture
PASS: 3 tests passed.

cargo fmt --check
FAIL: pre-existing formatting diff in crates/dom-wallet2/src/payment.rs:909.
This is outside Phase 1.3/1.4 and was not modified.

cargo clippy --workspace --all-targets -- -D warnings
PASS: finished successfully.

cargo test --workspace
PARTIAL: started and observed many suites passing, including dom-agent-runner,
dom-chain, dom-consensus, dom-core, dom-crypto, and multiple integration tests.
Final workspace summary was not captured before the session ended.

Security rg searches
Completed. Relevant reviewed hits were expected tests/comments or known unsafe
Send assertions in dom-node miner RandomX handles, outside monetary/balance scope.

git status --short / git diff --stat / git diff --check
PASS: no repository changes or diff output.
```

Temporary reproduction command:

```bash
cargo test -p dom-consensus validate_block_accepts_coinbase_kernel_with_plain_feature_when_constructed_in_memory -- --nocapture
```

Result:

```text
PASS as a proof of bug: current validate_block accepted the malformed in-memory coinbase.
The temporary test file was removed afterwards.
```

## 12. Files Changed

Persistent files changed:

- `/root/AUDIT_REPORT.md` - final audit report requested by the user.

Repository files changed:

- None.

Temporary files:

- `crates/dom-consensus/tests/temp_coinbase_feature.rs` was created for reproduction and removed immediately after the test.

## 13. Forbidden File Compliance

No repository file, forbidden or otherwise, was persistently modified.

No commits were created. No push was performed.

## 14. Remaining Risks

- Add the DOM-1.3-001 regression test and fix before mainnet.
- Clarify launch-facing monetary language so "halving" cannot be misread as strict 50% halving.
- Complete a later audit of P2P/RPC block ingress to prove every path reaches canonical deserialization or equally strict validation.
- Complete full workspace test capture in a dedicated run if required for release evidence.

## 15. Final Recommendation

Not ready for mainnet until DOM-1.3-001 is fixed and covered by regression tests. The serialized consensus path appears protected, but consensus validators should be construction-path independent before a Satoshi-style launch.
