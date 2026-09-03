#!/usr/bin/env bash
# scripts/f4_sepolia_slash.sh — the G-F4 Sepolia slash (F4 spec §12 item 3).
#
# Deploys (or reuses) the audited ConditionLockV2 through the ratified F3
# deploy path, then runs the one f4-harness Sepolia scenario. The exit code
# is not trusted alone: the scenario must have RUN (by name), nothing may
# have printed the skip marker, and libtest must report exactly 1 passed.
#
#   SEPOLIA_RPC_URL       endpoint serving the `finalized` tag (chain 11155111)
#   SEPOLIA_PRIVATE_KEY   the funded throwaway key (never printed)
#   SEPOLIA_LOCK          optional: reuse an existing ConditionLockV2
#   SEPOLIA_YES=1         non-interactive confirmation (the dispatch is consent)
#
# The key is exported once into the test environment and never echoed;
# `set -x` is never enabled in this file.
set -u -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

CAST="${CAST_BIN:-cast}"
EVIDENCE_DIR="${SEPOLIA_EVIDENCE_DIR:-$REPO_ROOT/artifacts/sepolia}"
mkdir -p "$EVIDENCE_DIR"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

[ -n "${SEPOLIA_RPC_URL:-}" ] || fail "SEPOLIA_RPC_URL is not set"
[ -n "${SEPOLIA_PRIVATE_KEY:-}" ] || fail "SEPOLIA_PRIVATE_KEY is not set"
if [ "${SEPOLIA_YES:-0}" != "1" ]; then
  printf 'This spends real Sepolia ETH and waits real finality (~40 min). Continue? [y/N] '
  read -r answer
  [ "$answer" = "y" ] || exit 1
fi

CHAIN_ID_HEX="$("$CAST" chain-id --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)" ||
  fail "the endpoint did not answer chain-id"
[ "$CHAIN_ID_HEX" = "11155111" ] || fail "endpoint is chain $CHAIN_ID_HEX, not Sepolia"

ACCOUNT="$("$CAST" wallet address --private-key "$SEPOLIA_PRIVATE_KEY" 2>/dev/null)" ||
  fail "could not derive the account address"
echo "== account $ACCOUNT =="
echo "   balance $("$CAST" balance "$ACCOUNT" --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null || echo '?') wei"

# Deployment: reuse when given, else run the ratified deploy script, which
# verifies the deployed runtime bytecode against the tree and waits finality.
if [ -z "${SEPOLIA_LOCK:-}" ]; then
  echo "== deploying ConditionLockV2 via scripts/sepolia_deploy.sh =="
  SEPOLIA_YES=1 "$REPO_ROOT/scripts/sepolia_deploy.sh" || fail "deployment failed"
  # The ratified deploy script writes its evidence to deploy.json (fixed
  # name); it verified the deployed runtime bytecode against this tree
  # and waited real finality before reporting success.
  DEPLOY_EVIDENCE="$EVIDENCE_DIR/deploy.json"
  [ -f "$DEPLOY_EVIDENCE" ] || fail "no deploy evidence at $DEPLOY_EVIDENCE"
  SEPOLIA_LOCK="$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["contracts"]["native"]["address"])
' "$DEPLOY_EVIDENCE")" || fail "could not read the deployed address"
else
  # Reuse path. On the deploy path, tree<->chain bytecode equality holds by
  # construction (forge script compiles this tree and deploys the result).
  # Reusing an address must not be weaker than deploying: rebuild the
  # runtime bytecode from this tree and require the chain to serve exactly
  # those bytes at the given address. ConditionLockV2 has no immutables,
  # so the comparison is byte-exact.
  echo "== verifying the runtime bytecode at $SEPOLIA_LOCK against this tree =="
  FORGE="${FORGE_BIN:-forge}"
  (cd "$REPO_ROOT/contracts" && "$FORGE" build >/dev/null 2>&1) ||
    fail "forge build failed"
  EXPECTED_CODE="$(cd "$REPO_ROOT/contracts" &&
    "$FORGE" inspect src/ConditionLockV2.sol:ConditionLockV2 deployedBytecode 2>/dev/null)" ||
    fail "could not derive the tree's runtime bytecode"
  ONCHAIN_CODE="$("$CAST" code "$SEPOLIA_LOCK" --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)" ||
    fail "eth_getCode failed for $SEPOLIA_LOCK"
  { [ -n "$ONCHAIN_CODE" ] && [ "$ONCHAIN_CODE" != "0x" ]; } ||
    fail "no code deployed at $SEPOLIA_LOCK"
  EXPECTED_LC="$(printf '%s' "$EXPECTED_CODE" | tr '[:upper:]' '[:lower:]')"
  ONCHAIN_LC="$(printf '%s' "$ONCHAIN_CODE" | tr '[:upper:]' '[:lower:]')"
  [ "$EXPECTED_LC" = "$ONCHAIN_LC" ] ||
    fail "runtime bytecode at $SEPOLIA_LOCK does not match this tree"
  echo "   runtime bytecode matches this tree byte-for-byte"
fi
echo "== ConditionLockV2 $SEPOLIA_LOCK =="

RUN_LOG="$EVIDENCE_DIR/f4-slash-$(date -u +%Y%m%dT%H%M%SZ).log"
EXPECTED_TEST="sepolia_slash_compensates_without_any_privileged_action"

# The test run below is hermetic (--offline). The one network step it
# needs is this fetch of the LOCKED dependency graph — including the
# dom-adaptor git dependency at the pinned rev — isolated here so a
# transient fetch failure retries without touching the test itself, and
# --locked keeps the lockfile authoritative (no resolver drift). A
# source that stays unreachable still fails the run after the last
# attempt.
for attempt in 1 2 3 4 5; do
  if cargo fetch --locked; then break; fi
  echo "cargo fetch attempt $attempt failed; retrying in $((attempt * 10))s"
  sleep $((attempt * 10))
done
cargo fetch --locked || fail "could not fetch the locked dependency graph"

F4_SEPOLIA_RPC="$SEPOLIA_RPC_URL" \
F4_SEPOLIA_LOCK="$SEPOLIA_LOCK" \
F4_SEPOLIA_ACCOUNT="$ACCOUNT" \
F4_SEPOLIA_KEY="$SEPOLIA_PRIVATE_KEY" \
F4_SEPOLIA_EVIDENCE_DIR="$EVIDENCE_DIR" \
F4_CAST="$CAST" \
  cargo test -p f4-harness --features rpc-http --offline --test e2e_sepolia \
  -- --nocapture --test-threads 1 2>&1 | tee "$RUN_LOG"
status="${PIPESTATUS[0]}"

verdict=0
grep -qE "^test ${EXPECTED_TEST} " "$RUN_LOG" || { echo "FAIL: the scenario never ran"; verdict=1; }
if grep -qF 'SKIPPED — NOTHING WAS VERIFIED' "$RUN_LOG"; then
  echo "FAIL: the run contains the skip marker"; verdict=1
fi
grep -qE '^test result: ok\. 1 passed; 0 failed;' "$RUN_LOG" ||
  { echo "FAIL: libtest did not report exactly 1 passed"; verdict=1; }
[ "$status" -eq 0 ] || { echo "FAIL: cargo test exited $status"; verdict=1; }

echo
if [ "$verdict" -eq 0 ]; then
  echo "VERDICT: G-F4 SEPOLIA SLASH PASS — see $EVIDENCE_DIR/f4-slash-evidence.json"
else
  echo "VERDICT: G-F4 SEPOLIA SLASH FAIL — see $RUN_LOG"
fi
exit "$verdict"
