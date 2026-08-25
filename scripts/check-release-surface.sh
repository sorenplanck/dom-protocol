#!/usr/bin/env bash
# Verify the Phase 1 production-build boundary required by G-UX1.
set -Eeuo pipefail

# Anchored to the workspace root, not to the git top level: in the monorepo
# these are different directories, and every path literal below is relative to
# the workspace the guarded crates belong to.
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

diagnostic="the evidence-only Store surface is forbidden in release builds"
log="$(mktemp -t dom-contracts-release-surface-XXXXXX)"
trap 'rm -f "$log"' EXIT

# The supported Store surface must remain compilable with release assertions.
cargo check --release --locked -p dom-scriptless-store

# Laboratory constructors must be impossible to include in the same build
# profile. Treat a different compiler failure as a failed gate so dependency or
# toolchain breakage cannot masquerade as the intended policy rejection.
if cargo check --release --locked -p dom-scriptless-store \
    --features evidence-only >"$log" 2>&1; then
  echo "release build unexpectedly accepted the evidence-only Store surface" >&2
  exit 1
fi

if ! grep -Fq "$diagnostic" "$log"; then
  echo "release build failed without the required evidence-only diagnostic" >&2
  tail -40 "$log" >&2
  exit 1
fi

echo "RELEASE_SURFACE = PASS"
