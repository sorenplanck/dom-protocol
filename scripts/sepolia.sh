#!/usr/bin/env bash
#
# scripts/sepolia.sh — THE single entry point for gate G-F3's Sepolia run.
#
#   export SEPOLIA_RPC_URL="https://<provider>/<key>"
#   export SEPOLIA_PRIVATE_KEY="0x…"        # funded with Sepolia ETH
#   ./scripts/sepolia.sh
#
# See docs/SEPOLIA-RUNBOOK.md for where to get those two values. Nothing else
# has to be prepared, installed, edited or exported.
#
# WHAT IT DOES, IN ORDER
# ----------------------
#   1. preflight — nine named checks, none of which spends anything;
#   2. a plan: how many transactions, roughly what it costs, roughly how long;
#   3. deploy (or reuse an existing deployment — see RESUMING);
#   4. the three settlement flows: DOM→EVM, EVM→DOM, and a refund driven by a
#      real wall-clock deadline, each with real finality;
#   5. the f3-harness integration tests, by name, against the same deployment;
#   6. machine-readable evidence, and one unambiguous verdict line.
#
# THE REFUSAL COMES FIRST
# -----------------------
# `chain_id` must be 11155111. Ethereum mainnet (1) is refused by name and
# everything else is refused generically. There is NO override flag, because a
# flag is exactly how a mainnet accident happens.
#
# Two checks run before it: `credentials` and `tooling`. Both are purely local
# — no network call and no transaction of any kind — and they exist only
# because `cast` is *how* the chain id is asked for. The very first thing this
# script sends to the endpoint is `eth_chainId`, and nothing is spent before
# the answer is 11155111.
#
# THE KEY
# -------
# `SEPOLIA_PRIVATE_KEY` is never printed, echoed, logged, written to a file, or
# rendered in a shell trace. Tracing is switched off at the top and again around
# the one command that receives it. Foundry mirrors broadcast material into
# `contracts/broadcast/` and `contracts/cache/`, so both trees are deleted by an
# EXIT trap installed before anything else happens — on the success path, the
# failure path and the refusal path alike.
#
# Named residue, recorded rather than papered over: `cast` 1.7.1 has no
# environment form of `--private-key` (`ETH_PRIVATE_KEY` is not read, and
# `--interactive` needs a TTY), and importing a keystore would write key
# material to disk, which is worse. The key therefore appears in the argument
# vector of one short-lived `cast wallet address` process, readable by the same
# user and by root. Run this on a machine where that is acceptable.
#
# RESUMING
# --------
# The deployment is durable evidence and is never redone needlessly. If
# `artifacts/sepolia/deploy.json` records a successful deployment whose
# addresses still carry the codehash of the contracts in this working tree, the
# run reuses it and says so. Re-running after any later failure therefore costs
# no redeployment. `--fresh-deployment` forces a new one.
#
# EXIT CODES
#   0  PASS               — every flow settled, was finalized and was recorded
#   1  REFUSED / FAIL     — wrong chain, or a phase failed
#   2  MISSING_ENV        — a required variable is absent
#   3  BLOCKED_EXTERNAL   — the endpoint does not serve the `finalized` tag
#   4  BLOCKED_EXTERNAL   — a bounded wait for finality timed out
#   5  PREFLIGHT_FAILED   — tooling, build, balance or workspace problem
#
# ALL OUTPUT AND COMMENTS IN ENGLISH (order constraint).

set -uo pipefail
# A shell trace renders every argument of every command, including the key.
# Turn it off here so `bash -x` on this script cannot leak it, and again at
# every site that touches the key.
set +x
set +v

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FOUNDRY_BIN="${FOUNDRY_BIN:-$HOME/.config/.foundry/bin}"
FORGE="${FORGE_BIN:-$FOUNDRY_BIN/forge}"
CAST="${CAST_BIN:-$FOUNDRY_BIN/cast}"

SEPOLIA_CHAIN_ID=11155111
MAINNET_CHAIN_ID=1

EVIDENCE_DIR="${SEPOLIA_EVIDENCE_DIR:-$REPO_ROOT/artifacts/sepolia}"
DEPLOY_EVIDENCE="$EVIDENCE_DIR/deploy.json"
E2E_EVIDENCE="$EVIDENCE_DIR/e2e.json"
GATE_EVIDENCE="$EVIDENCE_DIR/gate.json"
RUN_LOG="$EVIDENCE_DIR/run.log"

EXIT_OK=0
EXIT_REFUSED=1
EXIT_MISSING_ENV=2
EXIT_NO_FINALIZED_TAG=3
EXIT_FINALITY_TIMEOUT=4
EXIT_PREFLIGHT=5

# Total gas this run can consume, measured rather than guessed:
#
#   ConditionLockV2       1,457,370   |  measured on Anvil against this tree
#   ConditionLockERC20V2  1,691,944   |  (forge broadcast receipts)
#   forge deploy margin   1,000,000   |  the 2026-08-10 gate run showed forge
#                                     |  ESTIMATES the two deploys at ~4.09M
#                                     |  (its own margin over the measured
#                                     |  3.15M); the budget covers what forge
#                                     |  will demand, not only what is burned
#   6 settlement calls    1,800,000   |  3 flows x 2 calls, at the pinned
#                                     |  NATIVE_SETTLEMENT_GAS_LIMIT of 300,000
#   4 harness calls       1,200,000   |  2 direction tests x 2 calls
#   MockERC20 deploy        800,000   |  the ERC-20 fixture, with forge's margin
#   mint + 2 approvals      200,000   |  funding the funder, then per-flow
#   4 ERC-20 settlement   1,400,000   |  2 flows x 2 calls at 350,000: the
#                                     |  ERC-20 `open` pulls through
#                                     |  `transferFrom` and probes the balance
#                                     |  twice, so it is dearer than native
#   2 credit withdrawals    200,000   |  draining the pull credits the flows
#                                     |  leave, so the harness starts from zero
#   headroom                850,000
#                        ----------
#                        10,600,000
#
# The settlement figures are gas *limits*, not gas used (about 100k–170k each),
# so this is an upper bound on a run, not a forecast of the bill.
GAS_BUDGET=10600000
# The non-deploy remainder of the table (flows + harness + the ERC-20 leg +
# headroom): what a run still needs AFTER the deployment phase — the mid-run
# budget gate below. The ERC-20 fixture is deployed by the settlement phase, not
# by the deployment phase, so its gas belongs on this side of the line.
GAS_BUDGET_AFTER_DEPLOY=6450000

# Floor on the funding balance, whatever the gas price says. A faucet drip is
# typically 0.05–0.5 Sepolia ETH, so this rejects an account that was never
# funded rather than one that is merely thrifty.
BALANCE_FLOOR_WEI="${SEPOLIA_BALANCE_FLOOR_WEI:-20000000000000000}" # 0.02 ETH

# Safety factor on the estimated cost: Sepolia's base fee moves, and running out
# of gas halfway through is the one failure this preflight exists to prevent.
# 4x, not 2x: the 2026-08-10 gate run measured the price jumping 0.989 -> 2.06
# gwei between the preflight sample and forge's broadcast ONE SECOND later —
# ordinary volatility ate an entire 2x factor. A single sample is a point in a
# moving series; the factor must absorb the swing, and the mid-run gate below
# re-samples so a sustained rise refuses BEFORE spending, never mid-phase.
COST_SAFETY_FACTOR=4

ASSUME_YES="${SEPOLIA_YES:-0}"
PREFLIGHT_ONLY="${SEPOLIA_PREFLIGHT_ONLY:-0}"
FORCE_DEPLOY="${SEPOLIA_FORCE_DEPLOY:-0}"
SKIP_HARNESS="${SEPOLIA_SKIP_HARNESS:-0}"

# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------

usage() {
  cat <<'USAGE'
usage: ./scripts/sepolia.sh [options]

  --yes                 do not ask for confirmation before spending
  --preflight-only      run every check, print the plan, then stop
  --fresh-deployment    ignore any recorded deployment and deploy again
  --skip-harness        settlement flows only; skips the f3-harness phase
                        (about an hour shorter, but the DOM leg is then not
                        exercised on the testnet at all)
  -h, --help            this text

required environment:
  SEPOLIA_RPC_URL       Sepolia JSON-RPC endpoint (chain id 11155111)
  SEPOLIA_PRIVATE_KEY   funded deployer/settler key; never printed or persisted

see docs/SEPOLIA-RUNBOOK.md
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
  --yes | -y) ASSUME_YES=1 ;;
  --preflight-only) PREFLIGHT_ONLY=1 ;;
  --fresh-deployment) FORCE_DEPLOY=1 ;;
  --skip-harness) SKIP_HARNESS=1 ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    printf 'unknown option: %s\n\n' "$1" >&2
    usage >&2
    exit "$EXIT_REFUSED"
    ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------

log() { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }

# One preflight line per check, always with the check's own name, so a failure
# says which of the nine it was without anyone having to read the source.
PREFLIGHT_FAILED=0
pf() { printf '  %-8s %-18s %s\n' "$1" "$2" "$3"; }
pf_ok() { pf PASS "$1" "$2"; }
pf_bad() {
  pf FAIL "$1" "$2"
  PREFLIGHT_FAILED=1
}
pf_note() { printf '  %-8s %-18s %s\n' "" "" "$1"; }

die() {
  local code="$1"
  shift
  warn ""
  warn "$*"
  verdict_and_exit "$code" "$*"
}

# A refusal: the run was stopped on purpose and nothing was attempted.
refuse() {
  RESULT_OVERRIDE="REFUSED"
  die "$EXIT_REFUSED" "$*"
}

# ---------------------------------------------------------------------------
# key hygiene — installed before anything else can fail
# ---------------------------------------------------------------------------

# Foundry mirrors the whole broadcast, including material derived from the key
# it was handed, into contracts/broadcast/ and contracts/cache/. Neither tree
# may survive this script on ANY exit path, so removal is a trap rather than a
# line at the end.
purge_broadcast_artifacts() {
  local tree
  for tree in "$REPO_ROOT/contracts/broadcast" "$REPO_ROOT/contracts/cache"; do
    [ -d "$tree" ] || continue
    if command -v shred >/dev/null 2>&1; then
      find "$tree" -type f -exec shred -u {} + 2>/dev/null
    fi
    rm -rf "$tree"
  done
}
trap purge_broadcast_artifacts EXIT INT TERM

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

rpc() {
  local method="$1" params="$2"
  "$CAST" rpc --rpc-url "$SEPOLIA_RPC_URL" --raw "$method" "$params" 2>/dev/null
}

json_field() {
  python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(doc, dict):
    sys.exit(1)
v = doc.get(sys.argv[1])
if v is None:
    sys.exit(1)
print(v)
' "$1"
}

# Reads a dotted path out of a JSON file. Prints nothing and fails when absent.
json_path() {
  python3 -c '
import json, sys
try:
    node = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(1)
for part in sys.argv[2].split("."):
    if not isinstance(node, dict) or part not in node:
        sys.exit(1)
    node = node[part]
if node is None:
    sys.exit(1)
print(node)
' "$1" "$2"
}

# Arbitrary-precision decimal arithmetic. Wei quantities pass 2^63 routinely and
# the shell's integers do not, so nothing about money is computed in bash.
big() { python3 -c 'import sys; print(eval(sys.argv[1]))' "$1"; }

# Renders a wei amount as ETH with four decimals, for humans only.
wei_to_eth() {
  python3 -c '
import sys
from decimal import Decimal
print(f"{Decimal(sys.argv[1]) / Decimal(10) ** 18:.6f}")
' "$1"
}

# Prefixes every line with the elapsed time of the phase, so a long silence is
# visibly a wait rather than a hang.
stamp_lines() {
  python3 -u -c '
import sys, time
start = time.time()
for line in sys.stdin:
    elapsed = int(time.time() - start)
    sys.stdout.write("[%02d:%02d] %s" % (elapsed // 60, elapsed % 60, line))
    sys.stdout.flush()
'
}

# ---------------------------------------------------------------------------
# the verdict — the last line of every path through this script
# ---------------------------------------------------------------------------

RESULT="NOT_RUN"
RESULT_DETAIL="the run did not reach a verdict"
# A refusal is not a failure: nothing was attempted, let alone broken. It gets
# its own word in the verdict so nobody has to interpret one.
RESULT_OVERRIDE=""
DEPLOY_SOURCE="none"
NATIVE_LOCK=""
ERC20_LOCK=""
ACCOUNT=""
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STARTED_EPOCH="$(date +%s)"

verdict_and_exit() {
  local code="$1" detail="$2"
  if [ -n "$RESULT_OVERRIDE" ]; then
    RESULT="$RESULT_OVERRIDE"
    RESULT_DETAIL="$detail"
    write_gate_evidence
    log ""
    log "VERDICT: G-F3 SEPOLIA $RESULT — $detail"
    exit "$code"
  fi
  case "$code" in
  "$EXIT_OK") RESULT="PASS" ;;
  "$EXIT_MISSING_ENV") RESULT="MISSING_ENV" ;;
  "$EXIT_NO_FINALIZED_TAG") RESULT="BLOCKED_EXTERNAL" ;;
  "$EXIT_FINALITY_TIMEOUT") RESULT="BLOCKED_EXTERNAL" ;;
  "$EXIT_PREFLIGHT") RESULT="PREFLIGHT_FAILED" ;;
  *) RESULT="FAIL" ;;
  esac
  RESULT_DETAIL="$detail"
  write_gate_evidence
  local elapsed=$(($(date +%s) - STARTED_EPOCH))
  log ""
  log "== G-F3 / Sepolia =="
  log "  elapsed   $((elapsed / 60))m$((elapsed % 60))s"
  [ -n "$NATIVE_LOCK" ] && log "  contract  $NATIVE_LOCK (ConditionLockV2)"
  [ -n "$ERC20_LOCK" ] && log "  contract  $ERC20_LOCK (ConditionLockERC20V2)"
  [ -f "$DEPLOY_EVIDENCE" ] && log "  evidence  $DEPLOY_EVIDENCE"
  [ -f "$E2E_EVIDENCE" ] && log "  evidence  $E2E_EVIDENCE"
  [ -f "$GATE_EVIDENCE" ] && log "  evidence  $GATE_EVIDENCE  <- paste this into the G-F3 report"
  [ -f "$RUN_LOG" ] && log "  transcript $RUN_LOG"
  log ""
  log "VERDICT: G-F3 SEPOLIA $RESULT — $detail"
  exit "$code"
}

# Merges both evidence files into one document, adds everything only this
# script knows, and states the verdict inside the artifact as well as on screen.
write_gate_evidence() {
  command -v python3 >/dev/null 2>&1 || return 0
  mkdir -p "$EVIDENCE_DIR" 2>/dev/null || return 0
  SEP_RESULT="$RESULT" SEP_DETAIL="$RESULT_DETAIL" \
    SEP_STARTED="$STARTED_AT" SEP_FINISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    SEP_DEPLOY_SOURCE="$DEPLOY_SOURCE" SEP_NATIVE="$NATIVE_LOCK" SEP_ERC20="$ERC20_LOCK" \
    SEP_ACCOUNT="$ACCOUNT" SEP_FORGE="${FORGE_VERSION:-unknown}" \
    SEP_CAST="${CAST_VERSION:-unknown}" SEP_HARNESS="$SKIP_HARNESS" \
    SEP_LOCAL_NATIVE_CODEHASH="${LOCAL_NATIVE_CODEHASH:-}" \
    SEP_LOCAL_ERC20_CODEHASH="${LOCAL_ERC20_CODEHASH:-}" \
    python3 -c '
import json, os, sys

deploy_path, e2e_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

def load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None

doc = {
    "schema": "dom-interop/f3/sepolia-gate/v1",
    "gate": "G-F3",
    "network": {"name": "sepolia", "chainId": 11155111},
    "result": os.environ["SEP_RESULT"],
    "resultDetail": os.environ["SEP_DETAIL"],
    "startedAtUtc": os.environ["SEP_STARTED"],
    "finishedAtUtc": os.environ["SEP_FINISHED"],
    "deployment": {
        "source": os.environ["SEP_DEPLOY_SOURCE"],
        "conditionLockV2": os.environ["SEP_NATIVE"] or None,
        "conditionLockERC20V2": os.environ["SEP_ERC20"] or None,
        "expectedRuntimeCodehashFromThisTree": {
            "ConditionLockV2": os.environ["SEP_LOCAL_NATIVE_CODEHASH"] or None,
            "ConditionLockERC20V2": os.environ["SEP_LOCAL_ERC20_CODEHASH"] or None,
        },
    },
    "account": os.environ["SEP_ACCOUNT"] or None,
    "tooling": {"forge": os.environ["SEP_FORGE"], "cast": os.environ["SEP_CAST"]},
    "harnessPhaseSkipped": os.environ["SEP_HARNESS"] == "1",
    "deployEvidence": load(deploy_path),
    "e2eEvidence": load(e2e_path),
}
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2, sort_keys=True)
    fh.write("\n")
' "$DEPLOY_EVIDENCE" "$E2E_EVIDENCE" "$GATE_EVIDENCE" 2>/dev/null ||
    warn "could not write $GATE_EVIDENCE"
}

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------

FINALIZED_NUMBER=""
FINALIZED_HASH=""
FORGE_VERSION=""
CAST_VERSION=""
LOCAL_NATIVE_CODEHASH=""
LOCAL_ERC20_CODEHASH=""
GAS_PRICE_WEI=""
BALANCE_WEI=""
REQUIRED_WEI=""

# 1. credentials — local, no network, no spend.
check_credentials() {
  local missing=()
  # `${VAR:+set}` rather than `${VAR:-}`: the second renders the KEY ITSELF into
  # a shell trace, which is the one thing this script promises never to do. It
  # did, and `bash -x` found it. The first expands to "set" or to nothing, and
  # never to the value.
  [ -z "${SEPOLIA_RPC_URL:+set}" ] && missing+=("SEPOLIA_RPC_URL")
  [ -z "${SEPOLIA_PRIVATE_KEY:+set}" ] && missing+=("SEPOLIA_PRIVATE_KEY")
  if [ "${#missing[@]}" -gt 0 ]; then
    pf_bad credentials "missing: ${missing[*]}"
    pf_note "SEPOLIA_RPC_URL      Sepolia JSON-RPC endpoint (chain id $SEPOLIA_CHAIN_ID)"
    pf_note "SEPOLIA_PRIVATE_KEY  funded key; never printed or persisted by this script"
    pf_note "see docs/SEPOLIA-RUNBOOK.md for where to get both"
    return 1
  fi
  # The pieces this script drives read both from the environment. Exporting
  # here means `SEPOLIA_RPC_URL=… ./scripts/sepolia.sh` works as well as a
  # prior `export`, which is how an operator will actually type it.
  export SEPOLIA_RPC_URL SEPOLIA_PRIVATE_KEY
  export SEPOLIA_EVIDENCE_DIR="$EVIDENCE_DIR"
  export FOUNDRY_BIN FORGE_BIN="$FORGE" CAST_BIN="$CAST"
  pf_ok credentials "SEPOLIA_RPC_URL and SEPOLIA_PRIVATE_KEY are present"
  return 0
}

# 2. tooling — local, no network, no spend. Runs before the chain check only
#    because `cast` is how the chain is asked anything at all.
check_tooling() {
  local bad=0 bin
  for bin in "$FORGE" "$CAST"; do
    [ -x "$bin" ] || {
      pf_bad tooling "missing Foundry binary: $bin"
      pf_note "install Foundry, or set FOUNDRY_BIN / FORGE_BIN / CAST_BIN"
      bad=1
    }
  done
  command -v python3 >/dev/null 2>&1 || {
    pf_bad tooling "python3 is required to assemble the evidence files"
    bad=1
  }
  command -v cargo >/dev/null 2>&1 || {
    pf_bad tooling "cargo is required for the f3-harness phase"
    pf_note "or pass --skip-harness to run the settlement flows only"
    bad=1
  }
  [ "$bad" -eq 0 ] || return 1
  FORGE_VERSION="$("$FORGE" --version 2>/dev/null | head -1)"
  CAST_VERSION="$("$CAST" --version 2>/dev/null | head -1)"
  pf_ok tooling "${FORGE_VERSION:-forge} | ${CAST_VERSION:-cast}"
  return 0
}

# 3. chain-id — THE REFUSAL, and the first thing sent to the endpoint.
check_chain_id() {
  local chain_id
  chain_id="$("$CAST" chain-id --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)"
  if [ -z "$chain_id" ]; then
    pf_bad chain-id "the endpoint did not answer eth_chainId"
    pf_note "check SEPOLIA_RPC_URL: is the host reachable and the key valid?"
    return 1
  fi
  if [ "$chain_id" = "$MAINNET_CHAIN_ID" ]; then
    pf_bad chain-id "REFUSED: SEPOLIA_RPC_URL points at Ethereum mainnet (chain id 1)"
    pf_note "this project targets no L1 mainnet and there is no override flag"
    return 1
  fi
  if [ "$chain_id" != "$SEPOLIA_CHAIN_ID" ]; then
    pf_bad chain-id "REFUSED: endpoint chain id is $chain_id, expected $SEPOLIA_CHAIN_ID (Sepolia)"
    pf_note "there is no override flag: point SEPOLIA_RPC_URL at Sepolia"
    return 1
  fi
  pf_ok chain-id "$chain_id (Sepolia)"
  return 0
}

# 4. finalized-tag — A4-EVM has no fallback, so this is pass/BLOCKED, never a
#    degradation to a confirmation count.
check_finalized_tag() {
  local body number hash
  body="$(rpc eth_getBlockByNumber '["finalized",false]')"
  if [ -n "$body" ] && [ "$body" != "null" ]; then
    number="$(printf '%s' "$body" | json_field number)" || number=""
    hash="$(printf '%s' "$body" | json_field hash)" || hash=""
  fi
  if [ -z "${number:-}" ] || [ -z "${hash:-}" ]; then
    pf FAIL finalized-tag "BLOCKED_EXTERNAL: this endpoint does not serve the 'finalized' tag"
    pf_note "A4-EVM makes the Ethereum 'finalized' tag the only source of finality for"
    pf_note "this adapter, with no fallback: substituting a confirmation count would"
    pf_note "silently downgrade the safety property the settlement rests on. An endpoint"
    pf_note "that cannot answer eth_getBlockByNumber(\"finalized\") is unusable here."
    pf_note "This is a property of the PROVIDER, not a defect in this code: use another"
    pf_note "endpoint. Most hosted Sepolia endpoints serve the tag; some do not."
    return 2 # distinct: BLOCKED_EXTERNAL, not a failure of the code
  fi
  FINALIZED_NUMBER="$(printf '%d' "$number")"
  FINALIZED_HASH="$hash"
  pf_ok finalized-tag "served — finalized #$FINALIZED_NUMBER $FINALIZED_HASH"
  return 0
}

# 5. contracts-build — the contracts must compile HERE, and their runtime
#    codehashes are computed now so the deployment can be bound to this tree.
check_contracts_build() {
  if [ ! -d "$REPO_ROOT/contracts/lib/forge-std" ] ||
    [ ! -d "$REPO_ROOT/contracts/lib/openzeppelin-contracts" ]; then
    pf_bad contracts-build "contracts/lib is missing its dependencies"
    pf_note "run, once, from $REPO_ROOT/contracts:"
    pf_note "  forge install OpenZeppelin/openzeppelin-contracts@v5.1.0 --no-git"
    pf_note "  forge install foundry-rs/forge-std@v1.9.6 --no-git"
    return 1
  fi
  local out status
  out="$(cd "$REPO_ROOT/contracts" && "$FORGE" build 2>&1)"
  status=$?
  if [ "$status" -ne 0 ]; then
    pf_bad contracts-build "forge build failed (exit $status)"
    printf '%s\n' "$out" | tail -20 | sed 's/^/                              /'
    return 1
  fi
  LOCAL_NATIVE_CODEHASH="$(local_codehash ConditionLockV2)"
  LOCAL_ERC20_CODEHASH="$(local_codehash ConditionLockERC20V2)"
  if [ -z "$LOCAL_NATIVE_CODEHASH" ] || [ -z "$LOCAL_ERC20_CODEHASH" ]; then
    pf_bad contracts-build "built, but the runtime codehashes could not be computed"
    return 1
  fi
  pf_ok contracts-build "ConditionLockV2 $LOCAL_NATIVE_CODEHASH"
  pf_note "ConditionLockERC20V2 $LOCAL_ERC20_CODEHASH"
  return 0
}

# keccak256 of a contract's deployed bytecode, straight out of the Foundry
# artifact. This is what binds the on-chain deployment to this source tree.
local_codehash() {
  local artifact="$REPO_ROOT/contracts/out/$1.sol/$1.json" code
  [ -f "$artifact" ] || return 1
  code="$(python3 -c '
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
obj = doc.get("deployedBytecode", {}).get("object", "")
print(obj if obj.startswith("0x") else "0x" + obj)
' "$artifact" 2>/dev/null)"
  if [ -z "$code" ] || [ "$code" = "0x" ]; then
    return 1
  fi
  "$CAST" keccak "$code" 2>/dev/null
}

# The runtime codehash of a deployed address, as keccak256 of `eth_getCode`.
#
# NOT `cast codehash`, which is implemented over `eth_getProof`: that method is
# optional, several hosted Sepolia endpoints do not serve it, and a provider
# that refuses it would silently turn every codehash in the evidence into
# "unavailable" — losing precisely the field that binds the deployment to this
# source tree. `eth_getCode` is served by everything, and keccak of its answer
# is the same number by definition.
onchain_codehash() {
  local code
  code="$("$CAST" code "$1" --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)"
  if [ -z "$code" ] || [ "$code" = "0x" ]; then
    return 1
  fi
  "$CAST" keccak "$code" 2>/dev/null
}

# 6. funding-account — derive the public address. The key never leaves this
#    line, and this line never renders it.
check_funding_account() {
  set +x
  ACCOUNT="$("$CAST" wallet address --private-key "$SEPOLIA_PRIVATE_KEY" 2>/dev/null)"
  local status=$?
  set +x
  if [ "$status" -ne 0 ] || [ -z "$ACCOUNT" ]; then
    pf_bad funding-account "SEPOLIA_PRIVATE_KEY is not a usable secp256k1 key"
    pf_note "expected 0x followed by 64 hexadecimal characters"
    return 1
  fi
  pf_ok funding-account "$ACCOUNT"
  return 0
}

# 7. funding-balance — enough to finish, not merely enough to start.
check_funding_balance() {
  BALANCE_WEI="$("$CAST" balance "$ACCOUNT" --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)"
  if [ -z "$BALANCE_WEI" ]; then
    pf_bad funding-balance "the endpoint did not answer eth_getBalance for $ACCOUNT"
    return 1
  fi
  GAS_PRICE_WEI="$("$CAST" gas-price --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)"
  [ -n "$GAS_PRICE_WEI" ] || GAS_PRICE_WEI=0

  # Price what THIS run will actually do: when a recorded deployment is
  # usable (live on-chain codehash equal to this tree — the check runs
  # right here, after contracts-build computed the local codehashes),
  # the deploy phase spends nothing and requiring its gas would refuse
  # runs the account can comfortably afford. The verification standard
  # is unchanged: a deployment that fails the codehash comparison is
  # priced as a fresh deploy.
  local effective_budget="$GAS_BUDGET"
  if recorded_deployment_is_usable; then
    effective_budget="$GAS_BUDGET_AFTER_DEPLOY"
    pf_note "reusable deployment verified on chain; pricing the run without the deploy phase"
  fi

  local estimated
  estimated="$(big "$effective_budget * $GAS_PRICE_WEI")"
  if [ -n "${SEPOLIA_MIN_BALANCE_WEI:-}" ]; then
    REQUIRED_WEI="$SEPOLIA_MIN_BALANCE_WEI"
  else
    REQUIRED_WEI="$(big "max($BALANCE_FLOOR_WEI, $COST_SAFETY_FACTOR * $estimated)")"
  fi

  pf_note "gas price   $GAS_PRICE_WEI wei ($(python3 -c 'import sys;print(f"{int(sys.argv[1])/1e9:.3f}")' "$GAS_PRICE_WEI") gwei)"
  pf_note "gas budget  $effective_budget  =>  about $(wei_to_eth "$estimated") ETH at that price"
  pf_note "required    $(wei_to_eth "$REQUIRED_WEI") ETH (${COST_SAFETY_FACTOR}x the estimate, floor $(wei_to_eth "$BALANCE_FLOOR_WEI") ETH)"

  if [ "$(big "1 if $BALANCE_WEI >= $REQUIRED_WEI else 0")" != "1" ]; then
    pf_bad funding-balance "$(wei_to_eth "$BALANCE_WEI") ETH — below the required $(wei_to_eth "$REQUIRED_WEI") ETH"
    pf_note "fund $ACCOUNT from a Sepolia faucet (see docs/SEPOLIA-RUNBOOK.md),"
    pf_note "or set SEPOLIA_MIN_BALANCE_WEI if you know this requirement is too strict"
    return 1
  fi
  pf_ok funding-balance "$(wei_to_eth "$BALANCE_WEI") ETH available"
  return 0
}

# 8. harness-build — the integration phase runs an hour into the run, so its
#    test binary is compiled NOW rather than discovered to be broken then.
check_harness_build() {
  if [ "$SKIP_HARNESS" = "1" ]; then
    pf_ok harness-build "not needed (--skip-harness)"
    return 0
  fi
  local out status
  out="$(cd "$REPO_ROOT" && cargo test -p f3-harness \
    --features "${SEPOLIA_HARNESS_FEATURES:-rpc-http}" --test e2e_anvil --no-run 2>&1)"
  status=$?
  if [ "$status" -ne 0 ]; then
    pf_bad harness-build "the f3-harness test binary does not build (exit $status)"
    printf '%s\n' "$out" | tail -20 | sed 's/^/                              /'
    pf_note "or pass --skip-harness to run the settlement flows only"
    return 1
  fi
  pf_ok harness-build "e2e_anvil builds with features ${SEPOLIA_HARNESS_FEATURES:-rpc-http}"
  return 0
}

# 9. workspace — the evidence directory must be writable BEFORE anything is
#    spent, because an unrecordable run is a wasted run.
check_workspace() {
  if ! mkdir -p "$EVIDENCE_DIR" 2>/dev/null; then
    pf_bad workspace "cannot create $EVIDENCE_DIR"
    return 1
  fi
  if ! : >>"$RUN_LOG" 2>/dev/null; then
    pf_bad workspace "cannot write $RUN_LOG"
    return 1
  fi
  pf_ok workspace "$EVIDENCE_DIR is writable"
  return 0
}

preflight() {
  log "== preflight — nothing is spent until every check below passes =="
  check_credentials || die "$EXIT_MISSING_ENV" "a required environment variable is missing"
  check_tooling || die "$EXIT_PREFLIGHT" "the local toolchain is not ready"
  # The refusal. Nothing has been sent to the endpoint before this line.
  check_chain_id || refuse "the endpoint is not Sepolia"
  check_finalized_tag
  case "$?" in
  0) ;;
  2) die "$EXIT_NO_FINALIZED_TAG" "the endpoint does not serve the 'finalized' block tag; use a provider that does" ;;
  *) die "$EXIT_PREFLIGHT" "the finalized-tag check could not be completed" ;;
  esac
  check_contracts_build || die "$EXIT_PREFLIGHT" "the contracts do not build in this working tree"
  check_funding_account || die "$EXIT_PREFLIGHT" "the funding key is unusable"
  check_funding_balance || die "$EXIT_PREFLIGHT" "the funding account cannot pay for this run"
  check_harness_build || die "$EXIT_PREFLIGHT" "the f3-harness integration phase would not compile"
  check_workspace || die "$EXIT_PREFLIGHT" "the evidence directory is not usable"
  [ "$PREFLIGHT_FAILED" -eq 0 ] ||
    die "$EXIT_PREFLIGHT" "preflight failed; see the FAIL lines above"
  log ""
  log "  preflight passed: every foreseeable reason for this run to die halfway"
  log "  has been checked. What remains is the network's own behaviour."
}

# ---------------------------------------------------------------------------
# the plan — said out loud before a single wei is spent
# ---------------------------------------------------------------------------

announce_plan() {
  # The ERC-20 leg: the fixture's deploy and mint, then two flows of
  # (approve + open + settle). Its second flow waits out its own real deadline,
  # which is where its share of the wall clock goes.
  local flows_txs=6 erc20_txs=8 withdraw_txs=2 harness_txs=4 total minutes_lo minutes_hi
  if [ "$SKIP_HARNESS" = "1" ]; then
    harness_txs=0
    minutes_lo=43
    minutes_hi=63
  else
    minutes_lo=88
    minutes_hi=128
  fi
  local deploy_txs=2
  if [ "$DEPLOY_SOURCE" = "reused" ]; then
    deploy_txs=0
    minutes_lo=$((minutes_lo - 15))
    minutes_hi=$((minutes_hi - 15))
  fi
  total=$((deploy_txs + flows_txs + erc20_txs + withdraw_txs + harness_txs))

  log ""
  log "== what this run is about to do =="
  log "  network             Sepolia, chain id $SEPOLIA_CHAIN_ID"
  log "  account             $ACCOUNT"
  log "  balance             $(wei_to_eth "$BALANCE_WEI") ETH"
  log ""
  log "  transactions        $total"
  if [ "$deploy_txs" -gt 0 ]; then
    log "                        2  deploy ConditionLockV2 and ConditionLockERC20V2"
  else
    log "                        0  deploy (reusing the recorded deployment)"
  fi
  log "                        6  three settlement flows x (open + settle):"
  log "                             dom_to_evm  direction 0, settled by claim"
  log "                             evm_to_dom  direction 1, settled by claim"
  log "                             refund      opened, deadline waited out, refunded"
  log "                        8  the ERC-20 leg on ConditionLockERC20V2:"
  log "                             deploy and mint the MockERC20 fixture"
  log "                             erc20_dom_to_evm  direction 0, approve+open+claim"
  log "                             erc20_refund      direction 1, approve+open, deadline"
  log "                                               waited out, refunded"
  log "                             (operator-ratified addition of 2026-08-11; the"
  log "                              v0.14 gate text does not require this leg)"
  log "                        2  withdrawing the pull credits the flows leave, so"
  log "                             the harness starts from a zero credit balance"
  if [ "$harness_txs" -gt 0 ]; then
    log "                        4  f3-harness integration, two directions x (open + claim)"
  else
    log "                        0  f3-harness integration (skipped by request)"
  fi
  log ""
  log "  cost                budgeted up to $(wei_to_eth "$(big "$COST_SAFETY_FACTOR * $GAS_BUDGET * $GAS_PRICE_WEI")") ETH of gas"
  log "                      (${GAS_BUDGET} gas x the sampled price x the ${COST_SAFETY_FACTOR}x volatility"
  log "                       factor — the bound the balance check ENFORCED, not a"
  log "                       forecast; the sampled price is a moving number."
  log "                       Gas is the whole cost: each flow locks 1 wei and the"
  log "                       funder is also the beneficiary, so the value returns)"
  log ""
  log "  wall clock          ${minutes_lo}-${minutes_hi} minutes, and most of it is waiting."
  log "                      Sepolia finalizes about two epochs (~13 min) behind the"
  log "                      head, and this run waits for REAL finality several times:"
  log "                      once after the deployment, once after the flows, and"
  log "                      twice per harness direction. That wait is the A4-EVM rule"
  log "                      being obeyed, not a slow script."
  log ""
  log "  progress            every wait prints where it is, every 15 seconds."
  log "                      A silent stretch longer than a minute is a bug; a line"
  log "                      that says \"waiting for finality\" is not."
  log ""
  log "  if it dies          re-run the same command. The deployment is recorded in"
  log "                      $DEPLOY_EVIDENCE"
  log "                      and will be reused, so nothing is redeployed."
  log ""
}

confirm() {
  [ "$ASSUME_YES" = "1" ] && {
    log "  proceeding (--yes)"
    return 0
  }
  if [ ! -t 0 ]; then
    log "  stdin is not a terminal, so there is nobody to ask: proceeding."
    log "  Use --preflight-only to stop before spending."
    return 0
  fi
  printf '  Type "yes" to spend Sepolia ETH and start: '
  local answer=""
  read -r answer || answer=""
  if [ "$answer" != "yes" ]; then
    log "  not confirmed — nothing was sent."
    refuse "the operator did not confirm; nothing was spent"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# phases
# ---------------------------------------------------------------------------

# Runs one phase, stamping every line with the phase's elapsed time and keeping
# a transcript. Returns the phase's own exit status, not the pipeline's.
run_phase() {
  local label="$1"
  shift
  log ""
  log "== $label =="
  {
    printf '\n===== %s =====\n' "$label"
    printf 'started %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >>"$RUN_LOG"
  "$@" 2>&1 | stamp_lines | tee -a "$RUN_LOG"
  local status="${PIPESTATUS[0]}"
  printf 'exit %s at %s\n' "$status" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$RUN_LOG"
  return "$status"
}

# Is there a recorded deployment that still describes this working tree and is
# still on chain? Sets NATIVE_LOCK / ERC20_LOCK when so.
recorded_deployment_is_usable() {
  [ "$FORCE_DEPLOY" = "1" ] && return 1
  [ -f "$DEPLOY_EVIDENCE" ] || return 1
  [ "$(json_path "$DEPLOY_EVIDENCE" result 2>/dev/null)" = "OK" ] || return 1

  local native erc20
  native="$(json_path "$DEPLOY_EVIDENCE" contracts.native.address 2>/dev/null)" || return 1
  erc20="$(json_path "$DEPLOY_EVIDENCE" contracts.erc20.address 2>/dev/null)" || return 1
  [ -n "$native" ] && [ -n "$erc20" ] || return 1

  # The recorded addresses must still carry the codehash of THIS tree. Anything
  # else — a redeployed contract, an edited source file, someone else's
  # deployment — is not a resume, it is a different artefact.
  local on_native on_erc20
  on_native="$(onchain_codehash "$native")" || on_native="(no code at that address)"
  on_erc20="$(onchain_codehash "$erc20")" || on_erc20="(no code at that address)"
  if [ "$on_native" != "$LOCAL_NATIVE_CODEHASH" ] || [ "$on_erc20" != "$LOCAL_ERC20_CODEHASH" ]; then
    warn ""
    warn "  a deployment is recorded in $DEPLOY_EVIDENCE, but it does not match this tree:"
    warn "    ConditionLockV2       on chain $on_native"
    warn "                          expected $LOCAL_NATIVE_CODEHASH"
    warn "    ConditionLockERC20V2  on chain $on_erc20"
    warn "                          expected $LOCAL_ERC20_CODEHASH"
    warn "  it will NOT be reused. Pass --fresh-deployment to deploy this tree instead."
    return 1
  fi

  NATIVE_LOCK="$native"
  ERC20_LOCK="$erc20"
  return 0
}

phase_deploy() {
  if recorded_deployment_is_usable; then
    DEPLOY_SOURCE="reused"
    log ""
    log "== deployment =="
    log "  reusing the deployment recorded in $DEPLOY_EVIDENCE"
    log "  ConditionLockV2       $NATIVE_LOCK"
    log "  ConditionLockERC20V2  $ERC20_LOCK"
    log "  both runtime codehashes match the contracts built from this tree."
    log "  (pass --fresh-deployment to deploy again instead)"
    return 0
  fi

  DEPLOY_SOURCE="deployed"
  run_phase "deploying — 2 transactions, then a real wait for finality (~15 min)" \
    "$REPO_ROOT/scripts/sepolia_deploy.sh"
  local status=$?
  case "$status" in
  0) ;;
  "$EXIT_MISSING_ENV") die "$EXIT_MISSING_ENV" "the deploy step reported a missing environment variable" ;;
  "$EXIT_NO_FINALIZED_TAG") die "$EXIT_NO_FINALIZED_TAG" "the endpoint stopped serving the 'finalized' tag during deployment" ;;
  "$EXIT_FINALITY_TIMEOUT") die "$EXIT_FINALITY_TIMEOUT" "the deployment did not finalize inside the bounded wait" ;;
  *) die "$EXIT_REFUSED" "the deployment failed (exit $status); see $DEPLOY_EVIDENCE and $RUN_LOG" ;;
  esac

  NATIVE_LOCK="$(json_path "$DEPLOY_EVIDENCE" contracts.native.address 2>/dev/null)" || NATIVE_LOCK=""
  ERC20_LOCK="$(json_path "$DEPLOY_EVIDENCE" contracts.erc20.address 2>/dev/null)" || ERC20_LOCK=""
  if [ -z "$NATIVE_LOCK" ] || [ -z "$ERC20_LOCK" ]; then
    die "$EXIT_REFUSED" "the deployment reported success but $DEPLOY_EVIDENCE does not name both contracts"
  fi

  # The deployment must be the code in this tree, or every later claim about
  # what was tested is unfounded.
  local on_native on_erc20
  on_native="$(onchain_codehash "$NATIVE_LOCK")" || on_native="(no code at that address)"
  on_erc20="$(onchain_codehash "$ERC20_LOCK")" || on_erc20="(no code at that address)"
  if [ "$on_native" != "$LOCAL_NATIVE_CODEHASH" ] || [ "$on_erc20" != "$LOCAL_ERC20_CODEHASH" ]; then
    warn "  ConditionLockV2       on chain $on_native / expected $LOCAL_NATIVE_CODEHASH"
    warn "  ConditionLockERC20V2  on chain $on_erc20 / expected $LOCAL_ERC20_CODEHASH"
    die "$EXIT_REFUSED" "the deployed bytecode is not the bytecode this tree builds"
  fi
  log "  codehashes match the contracts built from this tree."
  return 0
}

phase_e2e() {
  local label="settlement flows — 6 transactions, a real deadline, real finality"
  [ "$SKIP_HARNESS" = "1" ] || label="$label, then the f3-harness phase"
  export SEPOLIA_LOCK="$NATIVE_LOCK"
  export SEPOLIA_ERC20_LOCK="$ERC20_LOCK"
  export SEPOLIA_SKIP_HARNESS="$SKIP_HARNESS"
  run_phase "$label" "$REPO_ROOT/scripts/sepolia_e2e.sh"
  local status=$?
  case "$status" in
  0) return 0 ;;
  "$EXIT_MISSING_ENV") die "$EXIT_MISSING_ENV" "the settlement step reported a missing environment variable" ;;
  "$EXIT_NO_FINALIZED_TAG") die "$EXIT_NO_FINALIZED_TAG" "the endpoint stopped serving the 'finalized' tag mid-run" ;;
  "$EXIT_FINALITY_TIMEOUT") die "$EXIT_FINALITY_TIMEOUT" "a bounded wait for finality timed out" ;;
  *) die "$EXIT_REFUSED" "a settlement flow failed (exit $status); see $E2E_EVIDENCE and $RUN_LOG" ;;
  esac
}

# The evidence must actually contain what the gate asks for: both directions, a
# refund, and a finality observation covering each. A green exit code from a
# step is not the same as evidence that the step produced.
verify_evidence() {
  local complaint
  complaint="$(python3 -c '
import json, sys

path = sys.argv[1]
skip_harness = sys.argv[2] == "1"
try:
    doc = json.load(open(path, encoding="utf-8"))
except Exception as exc:
    print(f"{path} is not readable as JSON ({exc})")
    raise SystemExit(0)

problems = []
result = doc.get("result")
if result != "OK":
    problems.append("result is " + repr(result) + ", not OK")

flows = doc.get("flows", {})
wanted = {
    "dom_to_evm": ("open", "claim"),
    "evm_to_dom": ("open", "claim"),
    "refund": ("open", "refund"),
    # The ERC-20 variant. Operator-ratified addition of 2026-08-11; the gate
    # text in Foundation Document v0.14 does not require it, so the closure
    # report must present it as an addition rather than as the criterion.
    "erc20_dom_to_evm": ("approve", "open", "claim"),
    "erc20_refund": ("approve", "open", "refund"),
}
for name, steps in wanted.items():
    flow = flows.get(name)
    if not isinstance(flow, dict):
        problems.append(f"flow {name} is absent")
        continue
    if not flow.get("settled"):
        problems.append(f"flow {name} is not marked settled")
    for step in steps:
        rec = flow.get("steps", {}).get(step)
        if not isinstance(rec, dict):
            problems.append(f"flow {name}: step {step} is absent")
            continue
        if not rec.get("txHash"):
            problems.append(f"flow {name}/{step}: no transaction hash")
        if rec.get("receipt", {}).get("status") != 1:
            problems.append(f"flow {name}/{step}: receipt status is not 1")
        if not rec.get("canonical"):
            problems.append(f"flow {name}/{step}: the block is not canonical")
        if not rec.get("finalizedCoversBlock"):
            problems.append(f"flow {name}/{step}: finality does not cover the block")

if flows.get("dom_to_evm", {}).get("direction") != 0:
    problems.append("dom_to_evm does not carry direction 0")
if flows.get("evm_to_dom", {}).get("direction") != 1:
    problems.append("evm_to_dom does not carry direction 1")

# Both direction values on the ERC-20 leg too, and each ERC-20 flow must name a
# token rather than the native asset — otherwise it is the native flow twice.
if flows.get("erc20_dom_to_evm", {}).get("direction") != 0:
    problems.append("erc20_dom_to_evm does not carry direction 0")
if flows.get("erc20_refund", {}).get("direction") != 1:
    problems.append("erc20_refund does not carry direction 1")
for name in ("erc20_dom_to_evm", "erc20_refund"):
    flow = flows.get(name, {})
    if flow.get("assetKind") != "erc20":
        problems.append(f"{name} is not marked as an erc20 flow")
    asset = flow.get("asset")
    if not isinstance(asset, str) or not asset.startswith("0x") or int(asset, 16) == 0:
        problems.append(f"{name} does not name a token address")

token = doc.get("token", {})
if not token.get("address"):
    problems.append("no ERC-20 fixture address was recorded")
if token.get("deploy", {}).get("receipt", {}).get("status") != 1:
    problems.append("the ERC-20 fixture deployment has no successful receipt")

if not skip_harness:
    harness = doc.get("harness", {})
    for name in ("anvil_dom_to_evm_direction", "anvil_evm_to_dom_direction"):
        rec = harness.get(name)
        if not isinstance(rec, dict) or not rec.get("ran") or not rec.get("passed"):
            problems.append(f"harness test {name} did not run and pass")

print("; ".join(problems))
' "$E2E_EVIDENCE" "$SKIP_HARNESS" 2>&1)"

  if [ -n "$complaint" ]; then
    warn ""
    warn "  the run exited 0 but the evidence is incomplete:"
    printf '    %s\n' "$complaint" >&2
    die "$EXIT_REFUSED" "the evidence does not establish the gate; see $E2E_EVIDENCE"
  fi
  log ""
  log "  evidence checked: both directions and the refund each have a transaction,"
  log "  a successful receipt, a canonical block and a finality observation covering it."
}

# ---------------------------------------------------------------------------

# Mid-run budget gate: a FRESH gas-price sample and a FRESH balance read,
# requiring the balance to cover the REMAINING gas units at the fresh price
# with the full safety factor. The preflight's sample ages by an hour before
# the later phases spend; this gate is how "PASS never dies mid-run" survives
# a sustained price rise — the run refuses BEFORE the next irreversible
# transaction, with the account intact, instead of failing after some of a
# phase's transactions have landed.
recheck_budget() { # recheck_budget <remaining-gas-units> <phase-name>
  local remaining_units="$1" phase="$2" price balance required
  price="$("$CAST" gas-price --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)"
  balance="$("$CAST" balance "$ACCOUNT" --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)"
  if [ -z "$price" ] || [ -z "$balance" ]; then
    # An unreadable endpoint is not a budget verdict; the phase's own
    # bounded retries own transient unavailability.
    log "  budget-gate         $phase: endpoint did not answer; proceeding on the phase's own retries"
    return 0
  fi
  required="$(big "$COST_SAFETY_FACTOR * $remaining_units * $price")"
  log "  budget-gate         $phase: balance $(wei_to_eth "$balance") ETH, needs $(wei_to_eth "$required") ETH"
  log "                      (${remaining_units} remaining gas x $(python3 -c 'import sys;print(f"{int(sys.argv[1])/1e9:.3f}")' "$price") gwei fresh sample x ${COST_SAFETY_FACTOR}x)"
  if [ "$(big "1 if $balance >= $required else 0")" != "1" ]; then
    die "$EXIT_PREFLIGHT" \
      "the $phase phase would start underfunded at the CURRENT gas price; refusing before spending (fund $ACCOUNT and re-run — the deployment is recorded and reusable)"
  fi
}

main() {
  log "G-F3 — DOM(dom-sim) <-> EVM settlement on the Sepolia testnet"
  log "started $STARTED_AT"
  log ""

  preflight

  # Whether a deployment can be reused changes the plan, so decide before
  # announcing it. This performs no transaction.
  if recorded_deployment_is_usable; then
    DEPLOY_SOURCE="reused"
  fi

  announce_plan

  if [ "$PREFLIGHT_ONLY" = "1" ]; then
    RESULT_OVERRIDE="PREFLIGHT_OK"
    verdict_and_exit "$EXIT_OK" "every check passed and nothing was spent; drop --preflight-only to run the gate"
  fi

  confirm

  phase_deploy
  recheck_budget "$GAS_BUDGET_AFTER_DEPLOY" "settlement/harness"
  phase_e2e
  verify_evidence

  verdict_and_exit "$EXIT_OK" \
    "both directions and the refund settled and finalized on chain id $SEPOLIA_CHAIN_ID"
}

# Executed normally: run everything. Sourced (by a test exercising one helper in
# isolation): define the functions and stop. Sourcing bypasses no check, because
# every check lives inside `main`, which a source does not call.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
