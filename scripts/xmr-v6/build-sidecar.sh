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
cargo build --release --locked
