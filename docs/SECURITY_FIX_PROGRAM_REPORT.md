# Security Fix Program Report

Date: 2026-06-26

This report consolidates the multi-session fix program executed after FIX-014.
All changes below are present in the working tree. They are not summarized by
commit history here because the tree contains both earlier FIX-014 work and the
follow-up hardening/funds-safety program.

## Completed Sessions

### Session 1 — Consensus / release blockers

- `FIX-014`
  - bounded aggregate `bp2` proof already applied in the tree
  - legacy unsafe helper re-export gated behind `test-helpers`
  - `secp256k1-zkp` dependency pinned by exact revision in `dom-crypto`
- `FIX-027`
  - ASERT carry-loss fixed in `crates/dom-pow/src/lib.rs`
  - regression added in `crates/dom-pow/tests/asert_mul_carry_xdiff.rs`
- Native-toolchain note
  - native `~/.cargo/bin/cargo` remains snap-confined in this environment
  - validation was executed under the temporary `/tmp` toolchain

### Session 2 — Funds-safety / transaction pipeline

- `FIX-022`
  - `crates/dom-slate/src/lib.rs`
  - `finalize` now verifies final output range proofs (`bp2_verify`)
- `FIX-007`
  - `crates/dom-faucet/src/lib.rs`
  - atomic IP-keyed rate limiting, no fail-open, bounded cleanup
- `FIX-005`
  - `crates/dom-wallet/src/backup.rs`
  - backup moved from XOR+SHA256 to authenticated `ChaCha20Poly1305`
- `FIX-023`
  - `crates/dom-wallet/src/journal.rs`
  - journal entries authenticated
- `FIX-024`
  - `crates/dom-wallet/src/journal.rs`
  - pending change blinding no longer persisted in plaintext

### Session 3 — Serialization / wallet arithmetic / derivation

- `FIX-028`
  - `crates/dom-serialization/src/lib.rs`
  - `read_list` now bounds by remaining bytes before allocation
- `FIX-032`
  - `crates/dom-wallet/src/output_index.rs`
  - coin-selection sum now uses checked arithmetic with explicit error
- `FIX-030`
  - `crates/dom-wallet-keys/src/hd_wallet.rs`
  - `derive_blinding` aligned to documented path
- `FIX-034`
  - `crates/dom-store/src/utxo.rs`
  - maturity path uses saturating arithmetic instead of panic
- `FIX-029`
  - `crates/dom-pow/src/lib.rs`
  - compact target projection made canonical/idempotent

### Session 4 — Protocol API / config / wallet app

- `FIX-033`
  - `crates/dom-tx/src/slate.rs`
  - unsupported `Slate.version` now rejected
  - `crates/dom-slate/src/lib.rs` validates version on receive/finalize
- `FIX-035`
  - `crates/dom-rpc/src/middleware.rs`
  - empty configured token and empty bearer token both rejected
- `FIX-036`
  - `crates/dom-config/src/lib.rs`
  - `NodeConfig` no longer serializes secrets and `Debug` redacts them
- `FIX-037`
  - `crates/dom-wallet-app/src/runtime.rs`
  - secret text redaction now covers multiword seed phrases
- `FIX-038`
  - `crates/dom-wallet-app/src/runtime.rs`
  - `crates/dom-wallet-app/src/storage.rs`
  - wallet-app `node_url` constrained to local `http/https`, no userinfo
- `FIX-031`
  - `crates/dom-core/src/address.rs`
  - mixed-case Bech32m address rejected instead of lowercased

### Session 5 — Node robustness / crypto edge cases

- `FIX-039`
  - `crates/dom-node/src/missing_block_tracker.rs`
  - caps on tracked missing parents and dependents per parent
- `FIX-040`
  - `crates/dom-node/src/node.rs`
  - peer violation scoring no longer uses over-broad substring coupling
- `FIX-041`
  - `crates/dom-wire/src/manager.rs`
  - pending ban reputation normalized to IP-only, preventing port-rotation evasion
- `FIX-043`
  - `crates/dom-wallet-keys/src/seed.rs`
  - public `spend_output_blinding` now rejects high-bit account/index values instead of masking them
  - `crates/dom-wallet-keys/tests/shield_blinding_collisions_proptest.rs`
  - RED aliasing tests converted into GREEN rejection regressions
- `FIX-044`
  - already closed by the current `bp2` implementation
  - `crates/dom-crypto/src/bulletproof_bp.rs` uses per-call `ScratchHandle`
  - DS-001 malformed-proof regression guardians remain in place

### Session 6 — Triaged / decided

- `FIX-042`
  - not dissolved: a real bug remained in persisted header resume validation
  - fixed in `crates/dom-chain/src/ibd.rs`
  - semantic invariant updated from `start <= last_progress <= blocks <= headers`
    to `start <= blocks <= last_progress <= headers`
  - this matches the live node behavior where header validation itself updates
    `last_progress_height`
- `FIX-008`
  - product decision codified: MuSig2 is deferred to v1.1
  - `docs/RELEASE_BLOCKERS.md` updated so MuSig2 absence is not treated as a
    v1.0 release blocker

## Focused Validation Completed

### Previously observed green in this program

- `cargo test -p dom-crypto`
  - completed with `0 failed`
  - included `bulletproof_bp::differential::random_1000_match`
- `cargo test -p dom-slate finalize_rejects_recipient_output_with_invalid_range_proof`
- `cargo test -p dom-faucet fix_007`
- `cargo test -p dom-wallet backup_file_roundtrip`
- `cargo test -p dom-wallet wrong_password_is_rejected`
- `cargo test -p dom-wallet --test shield_journal_forge_fix023`
- `cargo test -p dom-wallet --test shield_journal_blinding_fix024`
- `cargo test -p dom-serialization --test read_list_amplification`
- `cargo test -p dom-wallet select_for_spend_rejects_sum_overflow`
- `cargo test -p dom-wallet2 select_inputs_u64_sum_does_not_panic_on_overflow`
- `cargo test -p dom-wallet-keys --test derive_blinding_path_kav`
- `cargo test -p dom-pow --test compact_target_proptest`
- `cargo test -p dom-rpc empty_configured_token_never_authorizes`
- `cargo test -p dom-config debug_redacts_secret_fields`
- `cargo test -p dom-config serialization_omits_secret_fields`
- `cargo test -p dom-wallet-app multiword_seed_phrase_is_fully_redacted`
- `cargo test -p dom-wallet-app credentials_in_node_url_are_redacted`
- `cargo test -p dom-wallet-app tampered_node_url_with_hostile_scheme_is_rejected`
- `cargo test -p dom-wallet-app tampered_remote_node_url_is_rejected`
- `cargo test -p dom-core mixed_case_address_is_rejected`
- `cargo test -p dom-node --test shield_missing_block_tracker_flood`
- `cargo test -p dom-node --test shield_ban_port_rotation_kav`
- `cargo test -p dom-node shield_substring_match_is_position_independent_and_overmatches`

### Final validations run after the last fixes

- `cargo test -p dom-wallet-keys --test shield_blinding_collisions_proptest`
  - `6 passed; 0 failed`
- `cargo test -p dom-wallet2 --test shield_xdiff_blinding_byte_identity`
  - `3 passed; 0 failed`
- `cargo test -p dom-chain header_only_progress_above_blocks_accepted`
  - `1 passed; 0 failed`
- `cargo test -p dom-node persisted_header_resume_`
  - `3 passed; 0 failed`

## Files with the Highest-Signal Changes

- `crates/dom-chain/src/ibd.rs`
- `crates/dom-pow/src/lib.rs`
- `crates/dom-slate/src/lib.rs`
- `crates/dom-faucet/src/lib.rs`
- `crates/dom-wallet/src/backup.rs`
- `crates/dom-wallet/src/journal.rs`
- `crates/dom-wallet/src/output_index.rs`
- `crates/dom-wallet-keys/src/seed.rs`
- `crates/dom-wallet-app/src/runtime.rs`
- `crates/dom-wallet-app/src/storage.rs`
- `crates/dom-rpc/src/middleware.rs`
- `crates/dom-config/src/lib.rs`
- `crates/dom-node/src/missing_block_tracker.rs`
- `crates/dom-node/src/node.rs`
- `crates/dom-wire/src/manager.rs`
- `docs/RELEASE_BLOCKERS.md`

## Working Tree State

Current tree summary:

- modified tracked files: 43
- untracked items include:
  - `crates/dom-slate/tests/fix033_slate_version_validation.rs`
  - `docs/FIX-014_CORRECTION_PLAN.md`
  - `docs/FIX-014_IMPLEMENTATION_REPORT.md`
  - `docs/FIX-014_READONLY_REPORT.md`
  - local tooling/report folders

No attempt was made here to clean unrelated untracked local artifacts.
