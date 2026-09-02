#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SIDE="$ROOT/sidecar-gpl/xmr-live-sidecar-eigenwallet"
cd "$SIDE"
command -v cargo >/dev/null
cargo generate-lockfile
cargo update -p monero-oxide --precise c8be5d3d1287669946a83fbfcb296ce2a8852e47
if ! grep -q 'c8be5d3d1287669946a83fbfcb296ce2a8852e47' Cargo.lock; then
  echo 'monero-oxide source lock missing from Cargo.lock' >&2
  exit 1
fi
# The DOM deliverable is ONE workspace member: the sidecar binary. The host
# workspace (eigenwallet GUI, asb, swap CLI) is GPL scaffolding the sidecar
# is grafted into, not a DOM artifact; a bare `cargo build --release` here
# spent hours of fat-LTO on binaries nothing in the DOM tree consumes
# (narrowed 2026-09-02, Stage 13). The graft's integrity — the sidecar
# compiles as a member of the host workspace without breaking it — is
# attested by the workspace-wide check, which carries no LTO or final
# codegen cost.
cargo check --workspace --locked
cargo build --release --locked --package dom-xmr-sidecar
