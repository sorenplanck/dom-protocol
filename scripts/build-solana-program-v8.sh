#!/usr/bin/env bash
# Build dom-solana-escrow for its REAL target (sbf-solana-solana).
#
# The host `cargo test` builds the dalek fallback of `multiply_edwards`; only
# this build compiles the syscall path the deployed program runs. Verified
# 2026-09-01 with platform-tools v1.48 (rustc 1.84.1-dev):
#   dom_solana_escrow.so — see Cargo.lock in programs/dom-solana-escrow for
#   the exact pinned dependency set (several transitive crates are pinned
#   below their latest because platform-tools'\'' cargo predates edition2024).
set -euo pipefail
PT="${PLATFORM_TOOLS:-$HOME/platform-tools}"
if [ ! -x "$PT/rust/bin/cargo" ]; then
  echo "platform-tools not found at $PT" >&2
  echo "download: https://github.com/anza-xyz/platform-tools/releases/tag/v1.48" >&2
  exit 1
fi
cd "$(dirname "$0")/../programs/dom-solana-escrow"
exec "$PT/rust/bin/cargo" build --release --target sbf-solana-solana --lib --locked
