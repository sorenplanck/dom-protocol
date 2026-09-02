#!/usr/bin/env bash
# Sepolia — F3 end-to-end over the real network (no dev-node cheatcodes).
#
# RECONSTRUCTION (2026-09-02): rebuilt over the f3-harness env contract and
# the e2e_anvil.sh positive-coverage discipline; never existed here before.
#
# The f3-harness scenarios drive a live node through F3_ANVIL_* (the name is
# historical; the env is generic). On a real network the dev-node-only
# scenarios (reorg injection, mined-on-demand, crash-recovery) announce
# themselves with the harness's own "not a dev node" skip; this runner
# accepts exactly those skips and REQUIRES the core scenarios to run and
# pass. An empty or silently-shrunken suite fails the gate.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
source "$ROOT/scripts/sepolia.sh"

: "${SEPOLIA_NATIVE_LOCK:?SEPOLIA_NATIVE_LOCK is required (from sepolia_deploy.sh facts)}"
: "${SEPOLIA_ERC20_LOCK:?SEPOLIA_ERC20_LOCK is required (from sepolia_deploy.sh facts)}"

# Core scenarios that MUST start and pass on a real network.
EXPECTED_TESTS=(
  anvil_dom_to_evm_direction
  anvil_evm_to_dom_direction
  anvil_refund_by_deadline
  anvil_erc20_open_claim_and_observe
  anvil_erc20_refund_by_deadline
  anvil_pinned_signatures_still_match_the_compiled_contracts
)

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
set +e
F3_ANVIL_RPC="$SEPOLIA_RPC_URL" \
F3_ANVIL_LOCK="$SEPOLIA_NATIVE_LOCK" \
F3_ANVIL_ERC20_LOCK="$SEPOLIA_ERC20_LOCK" \
F3_ANVIL_ACCOUNT="$SEPOLIA_ACCOUNT" \
F3_ANVIL_KEY="$SEPOLIA_PRIVATE_KEY" \
cargo test -p f3-harness --test e2e_anvil -- --ignored --test-threads 1 \
  2>&1 | tee "$LOG"
status=$?
set -e

fail() { echo "SEPOLIA E2E GATE FAILED: $1" >&2; exit 1; }
for name in "${EXPECTED_TESTS[@]}"; do
  grep -qE "^test ${name} \.\.\. ok$" "$LOG" || fail "required scenario missing or not ok: ${name}"
done
grep -qE "^test result: .* 0 failed" "$LOG" || fail "suite reported failures"
[ "$status" -eq 0 ] || fail "cargo exit $status"
echo "SEPOLIA E2E GATE PASSED (${#EXPECTED_TESTS[@]} required scenarios green)"
