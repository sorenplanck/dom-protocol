#!/usr/bin/env bash
# NOTE on the line that moved. This list is `rustfmt --check` targets, nothing
# more: it never asserted a property about `crates/dom-crypto/src/scriptless.rs`
# beyond that file being formatted. That file belonged to the F7 node lineage
# and does not exist on the mainnet release line; its contents live here as
# `dom-scriptless-primitives`, beside the node rather than inside it. The entry
# is repointed at the bridge's own sources, so nothing is lost — there was no
# property to lose — and the script stops being permanently red.
set -euo pipefail

export CARGO_BUILD_JOBS=2

if [[ "${F7_VALIDATION_LOG_CHILD:-0}" != "1" && -n "${F7_EVIDENCE_DIR:-}" ]]; then
  mkdir -p "$F7_EVIDENCE_DIR"
  export F7_VALIDATION_LOG_CHILD=1
  exec "$0" 2>&1 | tee "$F7_EVIDENCE_DIR/dom-protocol-f7-surfaces-validation-final.log"
fi

cargo check -p dom-rpc -p dom-node -p dom-adaptor --all-targets
cargo test -p dom-adaptor transaction_lifecycle
cargo test -p dom-adaptor funding_authorization_restart_resumes_same_issuance_without_reissue --lib
cargo test -p dom-adaptor signing_share --lib
cargo test -p dom-adaptor shared_blinding_vault --lib
cargo test -p dom-adaptor vault_backed_nonce_material_is_sealed_before_commitment_and_restart_stable --lib
cargo test -p dom-adaptor two_party_driver_produces_a_739_byte_consensus_verifiable_proof --lib
cargo test -p dom-adaptor operational_session_uses_global_transcript_and_sender_sequence_bases --lib
cargo test -p dom-adaptor operational_only_store_marker_uses_the_complete_vault_backed_signer --lib
cargo test -p dom-adaptor --test scriptless_gate_readiness
cargo test -p dom-adaptor --test g1a_adaptor
cargo test -p dom-adaptor accepted_session_authority_is_static_and_fresh_replay_is_empty --lib
cargo test -p dom-adaptor accepted_session_rejects_mutated_initial_transcript_and_replay --lib
cargo test -p dom-adaptor --doc
cargo test -p dom-node scriptless_scan --lib
cargo test -p dom-node submit_tx_lost_ack --lib
cargo test -p dom-node --bin dom-node standalone_rpc
cargo test -p dom-rpc scriptless_scan --lib
cargo test -p dom-rpc submit_idempotent --lib
cargo test -p dom-wallet-recovery --lib
cargo test -p dom-rpc --lib
cargo test --manifest-path labs/dom-bp-migration-lab/Cargo.toml \
  distinct_backend_private_nonce_cannot_recover_a_valid_original_blinding
cargo clippy \
  -p dom-crypto -p dom-adaptor -p dom-wallet-core-api -p dom-node -p dom-rpc \
  --all-targets -- -D warnings \
  -A clippy::large-enum-variant -A dead-code \
  -A clippy::cloned-ref-to-slice-refs

rustfmt --edition 2021 --config skip_children=true --check \
  crates/dom-adaptor/src/adaptor.rs \
  crates/dom-adaptor/src/bulletproof_mpc.rs \
  crates/dom-adaptor/src/collaborative_bp_nonce_vault.rs \
  crates/dom-adaptor/src/collaborative_range_proof.rs \
  crates/dom-adaptor/src/funding_authority.rs \
  crates/dom-adaptor/src/lib.rs \
  crates/dom-adaptor/src/operational_funding_authority.rs \
  crates/dom-adaptor/src/signing_round.rs \
  crates/dom-adaptor/src/signing_share.rs \
  crates/dom-adaptor/src/shared_blinding_vault.rs \
  crates/dom-adaptor/src/transaction_lifecycle.rs \
  crates/dom-adaptor/src/vault_signer.rs \
  crates/dom-adaptor/tests/g1a_adaptor.rs \
  crates/dom-adaptor/tests/scriptless_gate_readiness.rs \
  crates/dom-crypto/src/bulletproof_bp.rs \
  crates/dom-crypto/src/lib.rs \
  crates/dom-scriptless-primitives/src/lib.rs \
  crates/dom-scriptless-primitives/src/curve.rs \
  crates/dom-node/src/main.rs \
  crates/dom-node/src/node.rs \
  crates/dom-node/src/node_handle.rs \
  crates/dom-node/src/wallet_core_api.rs \
  crates/dom-rpc/src/lib.rs \
  crates/dom-wallet-core-api/src/lib.rs \
  crates/dom-wallet-recovery/fuzz/fuzz_targets/fuzz_scanner_recovery_projection.rs \
  crates/dom-wallet-recovery/src/lib.rs

git diff --check
