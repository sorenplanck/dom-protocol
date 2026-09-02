#!/usr/bin/env bash
# Sepolia — F4 bond slash exercised on the real network.
#
# RECONSTRUCTION (2026-09-02): rebuilt over the F4_SEPOLIA_* env contract of
# crates/f4-harness/tests/e2e_sepolia.rs; never existed here before.
#
# Runs the one Sepolia scenario the harness ships —
# sepolia_slash_compensates_without_any_privileged_action — and requires it
# to actually START and PASS: the harness skips loudly without env, and a
# skipped run is a failed gate here, never a green one.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
source "$ROOT/scripts/sepolia.sh"

: "${F4_SEPOLIA_LOCK:?F4_SEPOLIA_LOCK is required (deployed bond lock address)}"
EVIDENCE_DIR="${F4_SEPOLIA_EVIDENCE_DIR:-$ROOT/contracts/release/f4-sepolia-evidence}"
mkdir -p "$EVIDENCE_DIR"

SCENARIO=sepolia_slash_compensates_without_any_privileged_action
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
set +e
F4_SEPOLIA_RPC="$SEPOLIA_RPC_URL" \
F4_SEPOLIA_LOCK="$F4_SEPOLIA_LOCK" \
F4_SEPOLIA_ACCOUNT="$SEPOLIA_ACCOUNT" \
F4_SEPOLIA_KEY="$SEPOLIA_PRIVATE_KEY" \
F4_SEPOLIA_EVIDENCE_DIR="$EVIDENCE_DIR" \
cargo test -p f4-harness --test e2e_sepolia -- --test-threads 1 2>&1 | tee "$LOG"
status=$?
set -e

fail() { echo "F4 SEPOLIA SLASH GATE FAILED: $1" >&2; exit 1; }
grep -qE "^test ${SCENARIO} \.\.\. ok$" "$LOG" || fail "scenario did not run and pass: ${SCENARIO}"
grep -q "did not run" "$LOG" && fail "harness announced a skip; env is incomplete"
[ "$status" -eq 0 ] || fail "cargo exit $status"
ls -A "$EVIDENCE_DIR" >/dev/null 2>&1 || fail "no evidence recorded in $EVIDENCE_DIR"
echo "F4 SEPOLIA SLASH GATE PASSED (evidence in $EVIDENCE_DIR)"
