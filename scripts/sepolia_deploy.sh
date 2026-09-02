#!/usr/bin/env bash
# Deploys ConditionLockV2 + ConditionLockERC20V2 to Sepolia (A9-EVM) and writes
# a machine-readable deployment evidence file.
#
# Environment, and nothing else:
#   SEPOLIA_RPC_URL          JSON-RPC endpoint for Sepolia               (required)
#   SEPOLIA_PRIVATE_KEY      key that pays for the deployment            (required)
#   SEPOLIA_EVIDENCE_DIR     where the JSON goes  (default: artifacts/sepolia)
#   SEPOLIA_FINALITY_TIMEOUT bounded finality wait, seconds  (default: 2400)
#   SEPOLIA_FINALITY_POLL    poll interval, seconds          (default: 15)
#   FOUNDRY_BIN/FORGE_BIN/CAST_BIN  where the Foundry binaries live
#
# Rules this script enforces, in this order:
#
#   1. both required variables must be present — otherwise it says exactly which
#      is missing and exits 2;
#   2. the endpoint's chain id must be 11155111. Anything else, and in
#      particular Ethereum mainnet (1), is refused. There is NO override flag,
#      because a flag is exactly how a mainnet accident happens;
#   3. the endpoint must serve the `finalized` block tag. A4-EVM has no
#      fallback: an endpoint without it cannot be used, and that is an external
#      blocker (BLOCKED_EXTERNAL), reported with its own exit code so it is not
#      confused with a refusal;
#   4. the key is never printed, echoed, written to a file or placed in a shell
#      trace. Tracing is switched off at the top and again around the one
#      command that receives the key; Foundry's broadcast and cache trees are
#      deleted afterwards, unconditionally, via a trap.
#
# Exit codes:
#   0  deployed, evidence written
#   1  refused (wrong chain, mainnet, missing tool, deployment failed)
#   2  missing required environment variable(s)
#   3  BLOCKED_EXTERNAL — the endpoint does not serve the `finalized` tag
#   4  BLOCKED_EXTERNAL — the bounded wait for finality timed out
#
# The contracts have no constructor argument and no privileged path of any kind,
# so the deployer is simply the account that paid for the code.

set -uo pipefail
# A shell trace renders every argument of every command, including the key.
# Turn it off here so `bash -x` on this script cannot leak it.
set +x
set +v

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FOUNDRY_BIN="${FOUNDRY_BIN:-$HOME/.config/.foundry/bin}"
FORGE="${FORGE_BIN:-$FOUNDRY_BIN/forge}"
CAST="${CAST_BIN:-$FOUNDRY_BIN/cast}"

SEPOLIA_CHAIN_ID=11155111
MAINNET_CHAIN_ID=1

EVIDENCE_DIR="${SEPOLIA_EVIDENCE_DIR:-$REPO_ROOT/artifacts/sepolia}"
EVIDENCE_FILE="$EVIDENCE_DIR/deploy.json"
FINALITY_TIMEOUT="${SEPOLIA_FINALITY_TIMEOUT:-2400}"
FINALITY_POLL="${SEPOLIA_FINALITY_POLL:-15}"

EXIT_REFUSED=1
EXIT_MISSING_ENV=2
EXIT_NO_FINALIZED_TAG=3
EXIT_FINALITY_TIMEOUT=4

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

log() { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
die() {
  local code="$1"
  shift
  warn "$*"
  exit "$code"
}

# Raw JSON-RPC through cast. `--raw` takes the params as one JSON array, so
# nothing is re-interpreted by the shell or by cast's argument guessing.
rpc() {
  local method="$1" params="$2"
  "$CAST" rpc --rpc-url "$SEPOLIA_RPC_URL" --raw "$method" "$params" 2>/dev/null
}

# Extracts one member from a JSON object on stdin. Prints nothing and fails when
# the input is not an object or the member is absent or null — a missing field is
# never turned into a default.
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

hex2dec() {
  local v="${1:-}"
  [ -n "$v" ] || return 1
  printf '%d' "$v" 2>/dev/null
}

# The runtime codehash of a deployed address, as keccak256 of `eth_getCode`.
#
# NOT `cast codehash`, which is implemented over `eth_getProof`: that method is
# optional and several hosted Sepolia endpoints do not serve it, which would
# turn the one field that binds this deployment to the source tree into
# "unavailable". `eth_getCode` is served by everything and keccak of its answer
# is the same number by definition.
runtime_codehash() {
  local code
  code="$("$CAST" code "$1" --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)"
  if [ -z "$code" ] || [ "$code" = "0x" ]; then
    return 1
  fi
  "$CAST" keccak "$code" 2>/dev/null
}

# ---------------------------------------------------------------------------
# evidence file
# ---------------------------------------------------------------------------

EV_FLAT=""

ev_open() {
  mkdir -p "$EVIDENCE_DIR" || die "$EXIT_REFUSED" "cannot create $EVIDENCE_DIR"
  EV_FLAT="$(mktemp "${TMPDIR:-/tmp}/sepolia-deploy-ev.XXXXXX")" ||
    die "$EXIT_REFUSED" "cannot create a temporary evidence buffer"
}

# ev_set <dotted.key> <value>. Values that look like integers or JSON literals
# are emitted as such; everything else becomes a JSON string.
ev_set() {
  [ -n "$EV_FLAT" ] || return 0
  printf '%s\t%s\n' "$1" "${2:-}" >>"$EV_FLAT"
}

ev_write() {
  [ -n "$EV_FLAT" ] || return 0
  python3 -c '
import json, re, sys

flat, out = sys.argv[1], sys.argv[2]
doc = {}
INT = re.compile(r"^-?[0-9]+$")
with open(flat, encoding="utf-8") as fh:
    for line in fh:
        line = line.rstrip("\n")
        if not line:
            continue
        key, _, raw = line.partition("\t")
        if raw in ("true", "false"):
            value = raw == "true"
        elif raw == "null":
            value = None
        elif INT.match(raw):
            value = int(raw)
        else:
            value = raw
        node = doc
        parts = key.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2, sort_keys=True)
    fh.write("\n")
' "$EV_FLAT" "$EVIDENCE_FILE" || warn "could not write $EVIDENCE_FILE"
  rm -f "$EV_FLAT"
  EV_FLAT=""
}

# ---------------------------------------------------------------------------
# finality
# ---------------------------------------------------------------------------

FINALIZED_NUMBER=""
FINALIZED_HASH=""

# Reads the `finalized` head into FINALIZED_NUMBER / FINALIZED_HASH.
# Non-zero when the endpoint cannot serve the tag — never a guess, never a
# confirmation count (A4-EVM).
finalized_head() {
  local body number hash
  body="$(rpc eth_getBlockByNumber '["finalized",false]')" || return 1
  [ -n "$body" ] || return 1
  [ "$body" = "null" ] && return 1
  number="$(printf '%s' "$body" | json_field number)" || return 1
  hash="$(printf '%s' "$body" | json_field hash)" || return 1
  FINALIZED_NUMBER="$(hex2dec "$number")" || return 1
  FINALIZED_HASH="$hash"
  [ -n "$FINALIZED_NUMBER" ] && [ -n "$FINALIZED_HASH" ]
}

# The probe from rule 3, run before anything is deployed.
require_finalized_tag() {
  if ! finalized_head; then
    warn "BLOCKED_EXTERNAL: this endpoint does not serve the 'finalized' block tag."
    warn ""
    warn "  A4-EVM makes the Ethereum 'finalized' tag the only source of finality"
    warn "  for this adapter, with no fallback: substituting a confirmation count"
    warn "  would silently downgrade the safety property the settlement rests on."
    warn "  An endpoint that cannot answer eth_getBlockByNumber(\"finalized\") is"
    warn "  therefore unusable here. This is a property of the provider, not of"
    warn "  the deployment: use an endpoint that serves the tag."
    exit "$EXIT_NO_FINALIZED_TAG"
  fi
  log "finalized  #$FINALIZED_NUMBER $FINALIZED_HASH"
}

# Bounded wait until the finalized head reaches $1. Sets FINALIZED_*.
wait_for_finality() {
  local target="$1" started elapsed
  started="$(date +%s)"
  while :; do
    if finalized_head && [ "$FINALIZED_NUMBER" -ge "$target" ]; then
      return 0
    fi
    elapsed=$(( $(date +%s) - started ))
    if [ "$elapsed" -ge "$FINALITY_TIMEOUT" ]; then
      warn "BLOCKED_EXTERNAL: timed out waiting for finality."
      warn "  needed  finalized >= block $target"
      warn "  reached finalized  = block ${FINALIZED_NUMBER:-unknown}"
      warn "  waited  ${elapsed}s of a ${FINALITY_TIMEOUT}s budget"
      warn ""
      warn "  Sepolia finalizes roughly two epochs (~13 min) behind the head."
      warn "  Raise SEPOLIA_FINALITY_TIMEOUT if the network is running slow;"
      warn "  do not work around this by weakening the finality rule."
      return 1
    fi
    log "  waiting for finality: finalized #${FINALIZED_NUMBER:-?} < $target (${elapsed}s/${FINALITY_TIMEOUT}s)"
    sleep "$FINALITY_POLL"
  done
}

# ---------------------------------------------------------------------------
# key hygiene
# ---------------------------------------------------------------------------

# Foundry mirrors the whole broadcast — including material derived from the key
# it was handed — into contracts/broadcast/ and contracts/cache/. Neither tree
# may survive this script, on any exit path, so removal is a trap and not a
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

# ---------------------------------------------------------------------------
# phases
# ---------------------------------------------------------------------------

require_environment() {
  local missing=()
  # `${VAR:+set}` rather than `${VAR:-}`: the second renders the KEY ITSELF into
  # a shell trace, which is the one thing this script promises never to do. It
  # did, and `bash -x` found it. The first expands to "set" or to nothing, and
  # never to the value.
  [ -z "${SEPOLIA_RPC_URL:+set}" ] && missing+=("SEPOLIA_RPC_URL")
  [ -z "${SEPOLIA_PRIVATE_KEY:+set}" ] && missing+=("SEPOLIA_PRIVATE_KEY")
  if [ "${#missing[@]}" -gt 0 ]; then
    warn "missing required environment variable(s): ${missing[*]}"
    warn ""
    warn "  SEPOLIA_RPC_URL      Sepolia JSON-RPC endpoint (chain id ${SEPOLIA_CHAIN_ID})"
    warn "  SEPOLIA_PRIVATE_KEY  deployer key; never printed or persisted by this script"
    warn ""
    warn "usage: SEPOLIA_RPC_URL=... SEPOLIA_PRIVATE_KEY=... $0"
    exit "$EXIT_MISSING_ENV"
  fi
}

require_tools() {
  local bin
  for bin in "$FORGE" "$CAST"; do
    [ -x "$bin" ] || die "$EXIT_REFUSED" "missing Foundry binary: $bin (set FOUNDRY_BIN)"
  done
  command -v python3 >/dev/null 2>&1 ||
    die "$EXIT_REFUSED" "python3 is required to assemble the evidence file"
}

# Rule 2. Runs before any transaction is even built.
require_sepolia() {
  local chain_id
  chain_id="$("$CAST" chain-id --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)"
  [ -n "$chain_id" ] ||
    die "$EXIT_REFUSED" "the endpoint did not answer eth_chainId; refusing to deploy"
  if [ "$chain_id" = "$MAINNET_CHAIN_ID" ]; then
    die "$EXIT_REFUSED" "REFUSED: SEPOLIA_RPC_URL points at Ethereum mainnet (chain id 1). This project targets no L1 mainnet and there is no override."
  fi
  if [ "$chain_id" != "$SEPOLIA_CHAIN_ID" ]; then
    die "$EXIT_REFUSED" "REFUSED: endpoint chain id is $chain_id, expected $SEPOLIA_CHAIN_ID (Sepolia). There is no override flag."
  fi
  log "chain id   $chain_id — Sepolia"
}

# Reads the address of a CREATE transaction for one contract out of Foundry's
# broadcast artifact. Prints nothing when it is not there.
read_deploy_field() {
  local run_json="$1" contract="$2" field="$3"
  python3 -c '
import json, sys
path, want, field = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    data = json.load(open(path, encoding="utf-8"))
except Exception:
    sys.exit(1)
for tx in data.get("transactions", []):
    if tx.get("transactionType") == "CREATE" and tx.get("contractName") == want:
        value = tx.get(field)
        if value is None:
            sys.exit(1)
        print(value)
        sys.exit(0)
sys.exit(1)
' "$run_json" "$contract" "$field"
}

# Records everything provable about one deployed contract.
record_contract() {
  local key="$1" name="$2" address="$3" tx_hash="$4"
  ev_set "contracts.$key.name" "$name"
  ev_set "contracts.$key.address" "$address"
  ev_set "contracts.$key.deployTxHash" "$tx_hash"

  local codehash receipt status block_number block_hash body
  codehash="$(runtime_codehash "$address")" || codehash=""
  ev_set "contracts.$key.runtimeCodehash" "${codehash:-unavailable}"

  receipt="$(rpc eth_getTransactionReceipt "[\"$tx_hash\"]")"
  if [ -z "$receipt" ] || [ "$receipt" = "null" ]; then
    ev_set "contracts.$key.receipt.present" "false"
    warn "no receipt for the deployment of $name ($tx_hash)"
    return 1
  fi
  ev_set "contracts.$key.receipt.present" "true"
  status="$(printf '%s' "$receipt" | json_field status)" || status=""
  block_number="$(printf '%s' "$receipt" | json_field blockNumber)" || block_number=""
  block_hash="$(printf '%s' "$receipt" | json_field blockHash)" || block_hash=""
  ev_set "contracts.$key.receipt.status" "$(hex2dec "${status:-0x0}")"
  ev_set "contracts.$key.deployBlockNumber" "$(hex2dec "${block_number:-0x0}")"
  ev_set "contracts.$key.deployBlockHash" "${block_hash:-unavailable}"

  # The block, fetched independently of the receipt, so the pair can be
  # cross-checked rather than believed one at a time.
  body="$(rpc eth_getBlockByNumber "[\"$block_number\",false]")"
  local canonical_hash=""
  if [ -n "$body" ] && [ "$body" != "null" ]; then
    canonical_hash="$(printf '%s' "$body" | json_field hash)" || canonical_hash=""
  fi
  ev_set "contracts.$key.canonicalBlockHash" "${canonical_hash:-unavailable}"
  if [ "$canonical_hash" != "$block_hash" ]; then
    ev_set "contracts.$key.canonical" "false"
    warn "the canonical block at ${block_number} is not the block the receipt names"
    return 1
  fi
  ev_set "contracts.$key.canonical" "true"

  [ "$(hex2dec "${status:-0x0}")" = "1" ] || {
    warn "the deployment of $name did not succeed (status $status)"
    return 1
  }

  # Finality proof for this deployment, observed now.
  local target
  target="$(hex2dec "$block_number")"
  wait_for_finality "$target" || return "$EXIT_FINALITY_TIMEOUT"
  ev_set "contracts.$key.finalizedAtObservation.number" "$FINALIZED_NUMBER"
  ev_set "contracts.$key.finalizedAtObservation.hash" "$FINALIZED_HASH"
  ev_set "contracts.$key.finalizedCoversDeployBlock" "true"
  log "  $name  $address  block $target  finalized #$FINALIZED_NUMBER"
  return 0
}

deploy() {
  log "== deploying =="
  cd "$REPO_ROOT/contracts" || die "$EXIT_REFUSED" "no contracts directory"

  # The one command that receives the key. Tracing is off, the command line is
  # never echoed, and the output is Foundry's own (which does not render the
  # key). `set +x` is repeated here so that a `set -x` introduced anywhere
  # above cannot reach this line.
  set +x
  EXPECTED_CHAIN_ID="$SEPOLIA_CHAIN_ID" "$FORGE" script script/Deploy.s.sol:DeployScript \
    --rpc-url "$SEPOLIA_RPC_URL" --broadcast --private-key "$SEPOLIA_PRIVATE_KEY"
  local status=$?
  set +x
  return "$status"
}

main() {
  trap purge_broadcast_artifacts EXIT INT TERM

  require_environment
  require_tools
  log "== checking the endpoint =="
  require_sepolia
  require_finalized_tag

  ev_open
  ev_set "schema" "dom-interop/f3/sepolia-deploy/v1"
  ev_set "network.name" "sepolia"
  ev_set "network.chainId" "$SEPOLIA_CHAIN_ID"
  ev_set "network.finalizedTagServed" "true"
  ev_set "network.finalizedAtStart.number" "$FINALIZED_NUMBER"
  ev_set "network.finalizedAtStart.hash" "$FINALIZED_HASH"
  ev_set "startedAtUtc" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  if ! deploy; then
    ev_set "result" "DEPLOY_FAILED"
    ev_write
    die "$EXIT_REFUSED" "deployment failed; evidence (such as it is) in $EVIDENCE_FILE"
  fi

  local run_json="$REPO_ROOT/contracts/broadcast/Deploy.s.sol/${SEPOLIA_CHAIN_ID}/run-latest.json"
  if [ ! -f "$run_json" ]; then
    ev_set "result" "NO_BROADCAST_ARTIFACT"
    ev_write
    die "$EXIT_REFUSED" "no broadcast artifact at $run_json"
  fi

  local native_addr native_tx erc20_addr erc20_tx
  native_addr="$(read_deploy_field "$run_json" ConditionLockV2 contractAddress)"
  native_tx="$(read_deploy_field "$run_json" ConditionLockV2 hash)"
  erc20_addr="$(read_deploy_field "$run_json" ConditionLockERC20V2 contractAddress)"
  erc20_tx="$(read_deploy_field "$run_json" ConditionLockERC20V2 hash)"

  if [ -z "$native_addr" ] || [ -z "$native_tx" ] || [ -z "$erc20_addr" ] || [ -z "$erc20_tx" ]; then
    ev_set "result" "INCOMPLETE_BROADCAST_ARTIFACT"
    ev_write
    die "$EXIT_REFUSED" "the broadcast artifact does not name both deployments"
  fi

  log "== recording deployment evidence =="
  local rc=0
  record_contract native ConditionLockV2 "$native_addr" "$native_tx" || rc=$?
  if [ "$rc" = "$EXIT_FINALITY_TIMEOUT" ]; then
    ev_set "result" "FINALITY_TIMEOUT"
    ev_write
    exit "$EXIT_FINALITY_TIMEOUT"
  fi
  local rc2=0
  record_contract erc20 ConditionLockERC20V2 "$erc20_addr" "$erc20_tx" || rc2=$?
  if [ "$rc2" = "$EXIT_FINALITY_TIMEOUT" ]; then
    ev_set "result" "FINALITY_TIMEOUT"
    ev_write
    exit "$EXIT_FINALITY_TIMEOUT"
  fi

  if [ "$rc" -ne 0 ] || [ "$rc2" -ne 0 ]; then
    ev_set "result" "EVIDENCE_INCOMPLETE"
    ev_write
    die "$EXIT_REFUSED" "the deployment could not be fully corroborated; see $EVIDENCE_FILE"
  fi

  ev_set "result" "OK"
  ev_set "finishedAtUtc" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  ev_write

  log ""
  log "== deployed on Sepolia (chain id ${SEPOLIA_CHAIN_ID}) =="
  log "  ConditionLockV2       $native_addr"
  log "  ConditionLockERC20V2  $erc20_addr"
  log "  evidence              $EVIDENCE_FILE"
  log ""
  log "export these for scripts/sepolia_e2e.sh:"
  log "  SEPOLIA_LOCK=$native_addr"
  log "  SEPOLIA_ERC20_LOCK=$erc20_addr"
}

# Executed normally: run everything. Sourced (by a test that wants to exercise
# one helper in isolation): define the functions and stop. Sourcing bypasses no
# check, because every check lives inside `main`, which a source does not call.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
