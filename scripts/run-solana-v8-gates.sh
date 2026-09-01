#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(pwd)}"
python3 "$ROOT/scripts/solana-v8-static-validate.py" "$ROOT"
cargo fmt --all -- --check
cargo test -p solana-escrow-wire -p solana-types -p solana-pda -p solana-route-secret -p solana-profile -p solana-setup-store -p solana-program-client -p solana-transaction-builder -p solana-rpc -p solana-rpc-pool -p solana-program-attestation -p solana-evidence -p solana-observer -p solana-observation-store -p solana-observer-pump -p solana-kaystra-records -p solana-kaystra-source -p solana-counterparty -p solana-delivery -p solana-delivery-sqlite -p solana-live -p solana-session-init -p solana-secret-store -p solana-kaystra-bridge -p solana-runtime-wiring -p f8-solana-model -p f8-solana-e2e -p solana-actuator -p xmr-actuator
cargo clippy -p solana-escrow-wire -p solana-types -p solana-pda -p solana-route-secret -p solana-profile -p solana-setup-store -p solana-program-client -p solana-transaction-builder -p solana-rpc -p solana-rpc-pool -p solana-program-attestation -p solana-evidence -p solana-observer -p solana-observation-store -p solana-observer-pump -p solana-kaystra-records -p solana-kaystra-source -p solana-counterparty -p solana-delivery -p solana-delivery-sqlite -p solana-live -p solana-session-init -p solana-secret-store -p solana-kaystra-bridge -p solana-runtime-wiring -p f8-solana-model -p f8-solana-e2e -p solana-actuator -p xmr-actuator --all-targets -- -D warnings
cargo test --manifest-path programs/dom-solana-escrow/Cargo.toml
# The production graph (dom-interopd children, materializer, F6) is feature-
# gated and invisible to default builds; it went uncompiled through three
# integration rounds. Never again:
cargo check -p dom-interopd --no-default-features --features production
