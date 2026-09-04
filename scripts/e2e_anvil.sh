#!/usr/bin/env bash
# G-F3 end-to-end harness: a local Anvil, the real ConditionLockV2, and the
# `f3-harness` integration tests.
#
# Everything this script does is local and disposable. It:
#   1. starts an Anvil on a fixed port and waits for it, by polling `cast
#      chain-id` in a bounded loop (no `sleep`: some shells here do not have a
#      usable foreground one);
#   2. deploys both lock contracts with `forge script`;
#   3. runs the `#[ignore]`d Anvil tests with the deployment in the environment;
#   4. ASSERTS, by name, that every expected scenario actually ran — see below;
#   5. shuts the node down cleanly, whatever happened.
#
# WHY STEP 4 EXISTS
# -----------------
# The tests in `crates/f3-harness/tests/e2e_anvil.rs` are `#[ignore]`d, which is
# the only exception this project allows, because they need a node the default
# gate does not have. An `#[ignore]`d suite is easy to render meaningless: a
# scenario that returns early still prints `ok`, and a scenario that is deleted
# takes its `ok` with it and the aggregate still says "test result: ok". Both
# have happened here.
#
# So the exit code of `cargo test` is NOT trusted on its own. This script
# requires, positively:
#
#   * every name in EXPECTED_TESTS started (`test <name> ...` in the output);
#   * no name outside EXPECTED_TESTS started, so a rename is caught too;
#   * the libtest summary reports exactly ${#EXPECTED_TESTS[@]} passed,
#     0 failed, 0 ignored, 0 filtered out;
#   * the marker `SKIPPED — NOTHING WAS VERIFIED` appears nowhere. Every skip
#     path in the harness prints it, and this script always drives a real
#     development node, so there is nothing here that may legitimately skip.
#
# The signing key is Anvil's first well-known development account. It is a
# public constant of the Foundry distribution, not a secret — and it is still
# never echoed: it is exported once and never printed, and `set -x` is never on.
#
# Usage:  ./scripts/e2e_anvil.sh [test-name-filter]
#
# A filter makes the run PARTIAL: the completeness assertion cannot apply, so it
# is not silently dropped — the script says so loudly and refuses to call the
# result a gate run.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FOUNDRY_BIN="${FOUNDRY_BIN:-$HOME/.config/.foundry/bin}"

# Resolution order per binary: an explicit *_BIN override wins verbatim; then
# the pinned FOUNDRY_BIN directory; then PATH. The PATH fallback is what CI
# needs — foundry-toolchain installs onto PATH, not under $HOME/.config — and
# the hard "missing Foundry binary" refusal below still fires when none of the
# three resolves.
resolve_foundry_bin() {
  # $1 = explicit override (may be empty), $2 = binary name
  if [ -n "$1" ]; then
    printf '%s\n' "$1"
  elif [ -x "$FOUNDRY_BIN/$2" ]; then
    printf '%s\n' "$FOUNDRY_BIN/$2"
  else
    command -v "$2" || printf '%s\n' "$FOUNDRY_BIN/$2"
  fi
}
ANVIL="$(resolve_foundry_bin "${ANVIL_BIN:-}" anvil)"
FORGE="$(resolve_foundry_bin "${FORGE_BIN:-}" forge)"
CAST="$(resolve_foundry_bin "${CAST_BIN:-}" cast)"
PORT="${F3_ANVIL_PORT:-8547}"
RPC="http://127.0.0.1:${PORT}"
CHAIN_ID=31337
LOG="${TMPDIR:-/tmp}/f3-anvil-${PORT}.log"

# Every scenario `crates/f3-harness/tests/e2e_anvil.rs` is expected to run, by
# name. This list is the contract between the harness and this script: adding a
# scenario without adding it here fails the run, and so does deleting one.
EXPECTED_TESTS=(
  anvil_dom_to_evm_direction
  log_pages_cover_every_block_exactly_once
  anvil_engine_crash_recovers_to_the_same_outcome
  anvil_erc20_deferred_payout_then_withdraw_in_instalments
  anvil_erc20_estimated_gas_silently_degrades_to_the_pull_path
  anvil_erc20_open_claim_and_observe
  anvil_erc20_refund_by_deadline
  anvil_evm_to_dom_direction
  anvil_pinned_signatures_still_match_the_compiled_contracts
  anvil_refund_by_deadline
  anvil_reorg_rewinds_to_the_common_ancestor_and_t_stays_known
  anvil_settlement_gas_limits_clear_the_deployed_push_threshold
)

# The F4 adversarial suite (`crates/f4-harness/tests/e2e_anvil.rs`) runs on
# the same node and the same deployment, under the same by-name contract.
F4_EXPECTED_TESTS=(
  anvil_cap_and_binding_refusals_touch_nothing
  anvil_release_path_is_executed_by_a_third_party
  anvil_reorg_across_the_claim_is_undecidable_not_a_verdict
  anvil_slash_path_survives_a_crash_at_every_transition
  anvil_uncertified_collateral_releases_by_timeout
  anvil_wrong_scalar_slash_reverts_on_chain
)

# The one marker that stands for "this scenario did not run". Kept byte-identical
# to `NOTHING_VERIFIED` in the harness and to `scad0::skip_banner`.
NOTHING_VERIFIED='SKIPPED — NOTHING WAS VERIFIED'

ARTIFACT_DIR="${F3_ANVIL_ARTIFACTS:-$REPO_ROOT/artifacts/anvil}"
RUN_LOG=""

# Anvil development account #0. Public, documented, funded on every Anvil.
ANVIL_ACCOUNT="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ANVIL_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

for bin in "$ANVIL" "$FORGE" "$CAST"; do
  if [ ! -x "$bin" ]; then
    echo "missing Foundry binary: $bin" >&2
    echo "set FOUNDRY_BIN, or ANVIL_BIN/FORGE_BIN/CAST_BIN, to point at your install" >&2
    exit 1
  fi
done

# The gate's cargo runs are `--offline` on purpose (see below): a network
# resolve in the middle of a run is a source of unrelated failures. That only
# works when the locked dependencies are already in the local cargo cache —
# true on a warmed developer machine, false on a cold CI runner, where the
# first `cargo test --offline` dies unable to check out the secp256k1-zkp git
# pin. So do ALL the network work here, up front, before the node even
# starts: fetch exactly what the lockfile pins, and fail loudly while failing
# is still cheap. The gate itself stays offline.
if ! cargo fetch --locked; then
  echo "cargo fetch --locked failed; the offline gate below cannot run without the pinned dependencies" >&2
  exit 1
fi

ANVIL_PID=""
# Reached only through the EXIT/INT/TERM trap below, which shellcheck cannot see.
# shellcheck disable=SC2317
cleanup() {
  if [ -n "$ANVIL_PID" ] && kill -0 "$ANVIL_PID" 2>/dev/null; then
    kill "$ANVIL_PID" 2>/dev/null
    # Bounded wait for a clean exit, then insist.
    for _ in $(seq 1 100); do
      kill -0 "$ANVIL_PID" 2>/dev/null || break
    done
    kill -0 "$ANVIL_PID" 2>/dev/null && kill -9 "$ANVIL_PID" 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

# `F3_ANVIL_EXTERNAL=1` means "a node is already listening on $RPC; use it and
# leave it alone". Needed in sandboxes where this script cannot own a
# long-running child process, and handy when iterating on a single test.
if [ "${F3_ANVIL_EXTERNAL:-0}" = "1" ]; then
  echo "== using the anvil already listening on ${RPC} =="
else
  echo "== starting anvil on ${RPC} =="
  setsid "$ANVIL" --port "$PORT" --chain-id "$CHAIN_ID" --silent \
    </dev/null >"$LOG" 2>&1 &
  ANVIL_PID=$!
  disown "$ANVIL_PID" 2>/dev/null || true
fi

ready=0
for _ in $(seq 1 600); do
  if "$CAST" chain-id --rpc-url "$RPC" >/dev/null 2>&1; then ready=1; break; fi
  if [ -n "$ANVIL_PID" ] && ! kill -0 "$ANVIL_PID" 2>/dev/null; then break; fi
done
if [ "$ready" -ne 1 ]; then
  echo "anvil did not become ready; see $LOG" >&2
  exit 1
fi

got_chain_id="$("$CAST" chain-id --rpc-url "$RPC")"
if [ "$got_chain_id" != "$CHAIN_ID" ]; then
  echo "unexpected chain id $got_chain_id (wanted $CHAIN_ID)" >&2
  exit 1
fi
echo "anvil ready, chain id $got_chain_id"

echo "== deploying ConditionLockV2 and ConditionLockERC20V2 =="
cd "$REPO_ROOT/contracts" || exit 1
EXPECTED_CHAIN_ID="$CHAIN_ID" "$FORGE" script script/Deploy.s.sol:DeployScript \
  --rpc-url "$RPC" --broadcast --private-key "$ANVIL_KEY" >/dev/null 2>&1
deploy_status=$?
if [ "$deploy_status" -ne 0 ]; then
  echo "forge script failed (exit $deploy_status)" >&2
  exit 1
fi

RUN_JSON="$REPO_ROOT/contracts/broadcast/Deploy.s.sol/${CHAIN_ID}/run-latest.json"
if [ ! -f "$RUN_JSON" ]; then
  echo "no broadcast artifact at $RUN_JSON" >&2
  exit 1
fi

read_addr() {
  python3 - "$RUN_JSON" "$1" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
want = sys.argv[2]
for tx in data.get("transactions", []):
    if tx.get("transactionType") == "CREATE" and tx.get("contractName") == want:
        print(tx["contractAddress"])
        break
PY
}

NATIVE_LOCK="$(read_addr ConditionLockV2)"
ERC20_LOCK="$(read_addr ConditionLockERC20V2)"
if [ -z "$NATIVE_LOCK" ] || [ -z "$ERC20_LOCK" ]; then
  echo "could not read the deployed addresses from $RUN_JSON" >&2
  exit 1
fi

# The adapter pins the codehash it reads at the `finalized` tag, so the
# deployment has to be finalized before anything can bind to it. Anvil answers
# `finalized` with `latest - 64`, so 70 instant blocks are enough. This is the
# whole of the "Anvil finality" accommodation: mine, then observe. The
# production finality rule is untouched.
"$CAST" rpc anvil_mine 0x46 --rpc-url "$RPC" >/dev/null 2>&1

echo "  ConditionLockV2       $NATIVE_LOCK"
echo "  codehash              $("$CAST" codehash "$NATIVE_LOCK" --rpc-url "$RPC")"
echo "  ConditionLockERC20V2  $ERC20_LOCK"
echo "  codehash              $("$CAST" codehash "$ERC20_LOCK" --rpc-url "$RPC")"

# --- test tokens for the ERC-20 leg ----------------------------------------
#
# Both come from the Solidity workstream's own mock file, unmodified:
#   * MockERC20  - a plain, well-behaved token. Its `transfer` fits inside the
#                  contract's 30k payout stipend, so the push succeeds and no
#                  credit is ever booked.
#   * HeavyToken - honest but expensive (it journals every transfer), so the
#                  push runs out of stipend and the payout degrades to a pull
#                  credit. That is the only way to reach `PayoutDeferred` and
#                  `withdraw`/`withdrawAmount` with a token that is not hostile.
deploy_token() {
  "$FORGE" create "test/mocks/HostileTokens.sol:$1" \
    --rpc-url "$RPC" --private-key "$ANVIL_KEY" --broadcast --json 2>/dev/null |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["deployedTo"])' 2>/dev/null
}

TOKEN="$(deploy_token MockERC20)"
HEAVY_TOKEN="$(deploy_token HeavyToken)"
if [ -z "$TOKEN" ] || [ -z "$HEAVY_TOKEN" ]; then
  echo "could not deploy the ERC-20 test tokens" >&2
  exit 1
fi

# One supply, minted to the single dev account that plays funder and
# beneficiary alike. 10^24 units is far more than any scenario locks.
MINT_AMOUNT=1000000000000000000000000
for tok in "$TOKEN" "$HEAVY_TOKEN"; do
  "$CAST" send "$tok" "mint(address,uint256)" "$ANVIL_ACCOUNT" "$MINT_AMOUNT" \
    --rpc-url "$RPC" --private-key "$ANVIL_KEY" >/dev/null 2>&1 || {
    echo "could not mint the ERC-20 test supply" >&2
    exit 1
  }
done

echo "  MockERC20 (plain)     $TOKEN"
echo "  HeavyToken (deferring)$HEAVY_TOKEN"

# Both tokens' code must also be finalized before the adapter can bind to a
# lock that names them.
"$CAST" rpc anvil_mine 0x46 --rpc-url "$RPC" >/dev/null 2>&1

# Foundry writes the broadcast key into contracts/cache/<script>/<chain>/. It is
# only Anvil's public dev key here, but the rule is the rule: do not leave key
# material lying around.
rm -rf "$REPO_ROOT/contracts/cache/Deploy.s.sol"

echo "== running the Anvil end-to-end suite =="
cd "$REPO_ROOT" || exit 1
FILTER="${1:-}"

# `rpc-http` is the only feature this run needs: it turns on the real HTTP
# transport so the harness talks to Anvil. The direction tests are gated to
# the backendless build and assert the DOM leg's NAMED refusal
# (`CryptoBackendDisabled`) — the EVM side is fully real either way (real
# contract, real deployment, real finalized `Claimed`). The positive DOM-leg
# halves (a real adaptation / byte-equal extraction) are proved against the
# frozen SCAD0 corpus in dom-leg's own conformance suite at the pin, not here;
# under B-DOM there is no separate `pin-integration` feature to enable.
#
# Set F3_FEATURES to override.
FEATURES="${F3_FEATURES:-rpc-http}"
echo "  cargo features        $FEATURES"

mkdir -p "$ARTIFACT_DIR" || {
  echo "cannot create $ARTIFACT_DIR" >&2
  exit 1
}
RUN_LOG="$ARTIFACT_DIR/e2e-$(date -u +%Y%m%dT%H%M%SZ).log"

# `--offline` because the lockfile is authoritative here and a network resolve
# in the middle of a gate run is a source of unrelated failures.
F3_ANVIL_RPC="$RPC" \
F3_ANVIL_LOCK="$NATIVE_LOCK" \
F3_ANVIL_ERC20_LOCK="$ERC20_LOCK" \
F3_ANVIL_TOKEN="$TOKEN" \
F3_ANVIL_HEAVY_TOKEN="$HEAVY_TOKEN" \
F3_ANVIL_ACCOUNT="$ANVIL_ACCOUNT" \
F3_ANVIL_KEY="$ANVIL_KEY" \
F3_CAST="$CAST" \
  cargo test -p f3-harness --features "$FEATURES" --offline --test e2e_anvil ${FILTER:+"$FILTER"} \
  -- --include-ignored --nocapture --test-threads 1 2>&1 | tee "$RUN_LOG"
status="${PIPESTATUS[0]}"

echo
echo "== transcript =="
echo "  $RUN_LOG"

# ---------------------------------------------------------------------------
# Completeness assertion — see the header. cargo's exit code is not enough.
# ---------------------------------------------------------------------------

if [ -n "$FILTER" ]; then
  echo
  echo "============================================================"
  echo "PARTIAL RUN — NOT A GATE RUN"
  echo "A test-name filter (\"$FILTER\") was supplied, so the by-name"
  echo "completeness assertion cannot apply and was not performed."
  echo "Run ./scripts/e2e_anvil.sh with no argument for a gate run."
  echo "============================================================"
  echo "== done (cargo exit $status) =="
  exit "$status"
fi

verdict=0
note() { printf '  %-8s %s\n' "$1" "$2"; }

echo
echo "== assertions on the run itself =="

# 1. Which scenarios actually started. With `--nocapture` libtest writes
#    `test <name> ... ` and only later the outcome, so the START of each line is
#    the reliable marker; the outcome is carried by the summary in (3).
started="$(grep -oE '^test [A-Za-z0-9_]+ \.\.\.' "$RUN_LOG" |
  sed -E 's/^test ([A-Za-z0-9_]+) \.\.\.$/\1/' | sort -u)"

missing=""
for want in "${EXPECTED_TESTS[@]}"; do
  printf '%s\n' "$started" | grep -qx "$want" || missing="$missing $want"
done
if [ -n "$missing" ]; then
  note FAIL "expected scenarios that never ran:$missing"
  verdict=1
else
  note ok "all ${#EXPECTED_TESTS[@]} expected scenarios ran, by name"
fi

expected_sorted="$(printf '%s\n' "${EXPECTED_TESTS[@]}" | sort -u)"
unexpected="$(comm -13 <(printf '%s\n' "$expected_sorted") <(printf '%s\n' "$started") | tr '\n' ' ')"
if [ -n "${unexpected// /}" ]; then
  note FAIL "scenarios ran that this script does not know about: $unexpected"
  note "" "add them to EXPECTED_TESTS, or find out why they exist"
  verdict=1
else
  note ok "no unknown scenario ran"
fi

# 2. The skip marker must not appear at all.
if grep -qF "$NOTHING_VERIFIED" "$RUN_LOG"; then
  note FAIL "the run contains \"$NOTHING_VERIFIED\":"
  grep -nF -B1 -A2 "$NOTHING_VERIFIED" "$RUN_LOG" | sed 's/^/           /'
  verdict=1
else
  note ok "nothing was skipped"
fi

# 3. libtest's own accounting, read positively rather than through $?.
summary="$(grep -E '^test result:' "$RUN_LOG" | tail -1)"
if [ -z "$summary" ]; then
  note FAIL "libtest printed no summary line at all"
  verdict=1
else
  count_of() { printf '%s' "$summary" | sed -nE "s/.* ([0-9]+) $1[;.].*/\1/p"; }
  n_passed="$(count_of passed)"
  n_failed="$(count_of failed)"
  n_ignored="$(count_of ignored)"
  n_filtered="$(printf '%s' "$summary" | sed -nE 's/.* ([0-9]+) filtered out.*/\1/p')"
  if [ "${n_passed:-0}" = "${#EXPECTED_TESTS[@]}" ] && [ "${n_failed:-1}" = "0" ] &&
    [ "${n_ignored:-1}" = "0" ] && [ "${n_filtered:-1}" = "0" ]; then
    note ok "$summary"
  else
    note FAIL "$summary"
    note "" "wanted ${#EXPECTED_TESTS[@]} passed; 0 failed; 0 ignored; 0 filtered out"
    verdict=1
  fi
fi

# 4. And only then, cargo's own status.
if [ "$status" -ne 0 ]; then
  note FAIL "cargo test exited $status"
  verdict=1
else
  note ok "cargo test exited 0"
fi

# ---------------------------------------------------------------------------
# F4 adversarial suite — same node, same deployment, same discipline.
# ---------------------------------------------------------------------------

RUN_LOG_F4="$ARTIFACT_DIR/e2e-f4-$(date -u +%Y%m%dT%H%M%SZ).log"
echo
echo "== F4 adversarial suite =="
F3_ANVIL_RPC="$RPC" \
F3_ANVIL_LOCK="$NATIVE_LOCK" \
F3_ANVIL_ACCOUNT="$ANVIL_ACCOUNT" \
F3_ANVIL_KEY="$ANVIL_KEY" \
F3_CAST="$CAST" \
  cargo test -p f4-harness --features rpc-http --offline --test e2e_anvil \
  -- --nocapture --test-threads 1 2>&1 | tee "$RUN_LOG_F4"
status_f4="${PIPESTATUS[0]}"

started_f4="$(grep -oE '^test [A-Za-z0-9_]+ \.\.\.' "$RUN_LOG_F4" |
  sed -E 's/^test ([A-Za-z0-9_]+) \.\.\.$/\1/' | sort -u)"
missing_f4=""
for want in "${F4_EXPECTED_TESTS[@]}"; do
  printf '%s\n' "$started_f4" | grep -qx "$want" || missing_f4="$missing_f4 $want"
done
if [ -n "$missing_f4" ]; then
  note FAIL "F4 scenarios that never ran:$missing_f4"
  verdict=1
else
  note ok "all ${#F4_EXPECTED_TESTS[@]} expected F4 scenarios ran, by name"
fi
if grep -qF "$NOTHING_VERIFIED" "$RUN_LOG_F4"; then
  note FAIL "the F4 run contains \"$NOTHING_VERIFIED\""
  verdict=1
else
  note ok "nothing was skipped in the F4 run"
fi
summary_f4="$(grep -E '^test result:' "$RUN_LOG_F4" | tail -1)"
if ! printf '%s' "$summary_f4" | grep -qE " ${#F4_EXPECTED_TESTS[@]} passed; 0 failed;"; then
  note FAIL "F4 summary: $summary_f4"
  verdict=1
else
  note ok "F4 summary: $summary_f4"
fi
if [ "$status_f4" -ne 0 ]; then
  note FAIL "F4 cargo test exited $status_f4"
  verdict=1
else
  note ok "F4 cargo test exited 0"
fi

# ---------------------------------------------------------------------------
# The run manifest (D-024 / F4 §12.4): the evidence a reader needs to tie
# this run to one HEAD and one deployment, without trusting the exit code.
# ---------------------------------------------------------------------------
MANIFEST="$ARTIFACT_DIR/anvil-manifest-$(date -u +%Y%m%dT%H%M%SZ).json"
TESTED_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD)"
WORKTREE_STATUS="$(git -C "$REPO_ROOT" status --short | wc -l | tr -d ' ')"
DEPLOYED_CODEHASH="$("$CAST" keccak "$("$CAST" code "$NATIVE_LOCK" --rpc-url "$RPC")" 2>/dev/null || echo unavailable)"
{
  echo "{"
  echo "  \"schema\": \"dom-interop/f4/anvil-manifest/v1\","
  echo "  \"testedHead\": \"$TESTED_HEAD\","
  echo "  \"dirtyWorktreeEntries\": $WORKTREE_STATUS,"
  echo "  \"chainId\": \"$CHAIN_ID\","
  echo "  \"contract\": \"$NATIVE_LOCK\","
  echo "  \"deployedRuntimeCodehash\": \"$DEPLOYED_CODEHASH\","
  echo "  \"f3Scenarios\": $(printf '%s\n' "${EXPECTED_TESTS[@]}" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read().split()))'),"
  echo "  \"f4Scenarios\": $(printf '%s\n' "${F4_EXPECTED_TESTS[@]}" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read().split()))'),"
  echo "  \"observedRefusals\": $(grep -oE 'manifest: refusal [a-z-]+ = .*' "$RUN_LOG_F4" | python3 -c 'import json,sys;print(json.dumps([l.strip() for l in sys.stdin]))'),"
  echo "  \"txCountDuringRefusals\": $(grep -oE 'manifest: tx-count-during-refusals = [0-9]+' "$RUN_LOG_F4" | grep -oE '[0-9]+$' || echo null),"
  echo "  \"journal\": $(grep -oE 'manifest: journal-terminal = .*' "$RUN_LOG_F4" | tail -1 | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read().strip()))'),"
  echo "  \"f3Summary\": $(grep -E '^test result:' "$RUN_LOG" | tail -1 | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read().strip()))'),"
  echo "  \"f4Summary\": $(printf '%s' "$summary_f4" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read().strip()))'),"
  echo "  \"verdict\": $([ "$verdict" -eq 0 ] && echo -n '"PASS"' || echo -n '"FAIL"')"
  echo "}"
} >"$MANIFEST"
note ok "manifest written: $MANIFEST"

echo
if [ "$verdict" -eq 0 ]; then
  echo "VERDICT: ANVIL E2E PASS — ${#EXPECTED_TESTS[@]}+${#F4_EXPECTED_TESTS[@]} scenarios ran and passed on chain id $CHAIN_ID"
else
  echo "VERDICT: ANVIL E2E FAIL — see the assertions above, $RUN_LOG and $RUN_LOG_F4"
fi
exit "$verdict"
