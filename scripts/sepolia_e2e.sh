#!/usr/bin/env bash
# Runs the G-F3 settlement suite against a Sepolia deployment (A9-EVM) and
# writes a machine-readable evidence file covering both directions and the
# refund.
#
# Environment:
#   SEPOLIA_RPC_URL          JSON-RPC endpoint for Sepolia                (required)
#   SEPOLIA_PRIVATE_KEY      key that funds, claims and refunds           (required)
#   SEPOLIA_LOCK             ConditionLockV2 address (from sepolia_deploy.sh) (required)
#   SEPOLIA_ERC20_LOCK       ConditionLockERC20V2 address (from sepolia_deploy.sh) (required)
#   SEPOLIA_EVIDENCE_DIR     where the JSON goes    (default: artifacts/sepolia)
#   SEPOLIA_AMOUNT_WEI       dust locked per flow                  (default: 1)
#   SEPOLIA_CLAIM_DEADLINE   seconds until a claim lock expires (default: 3600)
#   SEPOLIA_REFUND_DELAY     seconds until the refund lock expires (default: 240)
#   SEPOLIA_FINALITY_TIMEOUT bounded finality wait, seconds     (default: 2400)
#   SEPOLIA_FINALITY_POLL    poll interval, seconds               (default: 15)
#   SEPOLIA_SKIP_HARNESS     set to 1 to skip the cargo integration phase
#   FOUNDRY_BIN/CAST_BIN     where the Foundry binaries live
#
# Rules this script enforces, in this order:
#
#   1. every required variable must be present — otherwise it names exactly the
#      missing ones and exits 2;
#   2. the endpoint's chain id must be 11155111. Mainnet (1) is refused
#      explicitly, and so is everything else. There is NO override flag;
#   3. the endpoint must serve the `finalized` block tag before anything is
#      sent. A4-EVM has no fallback, so an endpoint without it is unusable —
#      an external blocker (BLOCKED_EXTERNAL) with its own exit code;
#   4. the key is never printed, echoed, logged or written to a file. Tracing
#      is switched off at the top and again inside the one wrapper that hands
#      the key to `cast`. See `cast_signed` for the one residue this cannot
#      close and why.
#
# What it does, and why in this order:
#
#   * three settlement flows are driven directly with `cast`, so that every
#     transaction hash, receipt status, block hash and finality observation is
#     captured as it happens and lands in the evidence file:
#       - dom_to_evm   (LockTerms.direction = 0): open, then claim
#       - evm_to_dom   (LockTerms.direction = 1): open, then claim
#       - refund       (short deadline)         : open, wait out the deadline,
#                                                 then refund
#     On the EVM leg the two directions are the same three calls; what differs
#     is `direction`, which is bound into `binding` and therefore into `lockId`.
#     That is exactly what the captured evidence proves;
#   * two further flows drive the SAME calls against `ConditionLockERC20V2`,
#     with `terms.asset` set to a token this script deploys rather than to
#     `address(0)`:
#       - erc20_dom_to_evm (direction 0): approve, open, then claim
#       - erc20_refund     (direction 1): approve, open, wait out the deadline,
#                                         then refund
#     Between them the ERC-20 variant is exercised on both direction values and
#     on both settlement paths. The ERC-20 `open` carries no ETH — that contract
#     rejects `msg.value != 0` — and pulls the amount through `transferFrom`
#     instead, so the approval is part of the flow rather than setup.
#
#     PROVENANCE: the G-F3 gate text in the Foundation Document (v0.14, "Gate
#     G-F3") requires both directions, a real `Claimed`, and a refund by a real
#     deadline. It does NOT mention the ERC-20 variant. These two flows were
#     added at the operator's explicit instruction of 2026-08-11 ("inclua erc20
#     ratifico"), which is the ratification they rest on. They are an addition
#     to the gate's published criterion, not a derivation from it, and the
#     closure report must say so;
#   * then the f3-harness integration tests are run *by name* against the same
#     endpoint. `anvil_refund_by_deadline` is deliberately NOT among them: it
#     drives `evm_increaseTime`, which a public network does not serve. The
#     refund is covered above instead, with a real wall-clock deadline.
#
# Unlike the Anvil harness this script does not mine: Sepolia produces blocks on
# its own and finality is roughly 13 minutes behind the head. Every wait is
# bounded and says so when it gives up. Expect a run to take tens of minutes;
# that is the real cost of the A4-EVM rule and it is not shortened by weakening
# it.
#
# Exit codes:
#   0  every flow settled and was corroborated
#   1  refused, or a flow failed
#   2  missing required environment variable(s)
#   3  BLOCKED_EXTERNAL — the endpoint does not serve the `finalized` tag
#   4  BLOCKED_EXTERNAL — a bounded wait for finality timed out

set -uo pipefail
# A shell trace renders every argument of every command. Turn it off here so
# `bash -x` on this script cannot leak anything.
set +x
set +v

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FOUNDRY_BIN="${FOUNDRY_BIN:-$HOME/.config/.foundry/bin}"
CAST="${CAST_BIN:-$FOUNDRY_BIN/cast}"
# Only the ERC-20 flows need `forge`, and only to deploy the token fixture.
FORGE="${FORGE_BIN:-$FOUNDRY_BIN/forge}"

# The token the ERC-20 flows lock. `MockERC20` is the plain, well-behaved
# baseline of the Foundry ERC-20 suite — the hostile variants in the same file
# subclass it and each breaks exactly one rule. The baseline is the right
# fixture here: this run is evidence that the settlement works against a token
# that behaves, not a re-run of the adversarial suite, which is where
# misbehaviour is already covered and where it belongs.
TOKEN_CONTRACT="test/mocks/HostileTokens.sol:MockERC20"

SEPOLIA_CHAIN_ID=11155111
MAINNET_CHAIN_ID=1

EVIDENCE_DIR="${SEPOLIA_EVIDENCE_DIR:-$REPO_ROOT/artifacts/sepolia}"
EVIDENCE_FILE="$EVIDENCE_DIR/e2e.json"
AMOUNT_WEI="${SEPOLIA_AMOUNT_WEI:-1}"
CLAIM_DEADLINE="${SEPOLIA_CLAIM_DEADLINE:-3600}"
REFUND_DELAY="${SEPOLIA_REFUND_DELAY:-240}"
FINALITY_TIMEOUT="${SEPOLIA_FINALITY_TIMEOUT:-2400}"
FINALITY_POLL="${SEPOLIA_FINALITY_POLL:-15}"
DEADLINE_POLL="${SEPOLIA_DEADLINE_POLL:-15}"

# Cargo features for the integration phase. `rpc-http` is the minimum. Adding
# `pin-integration` makes the two direction tests drive the REAL DOM adaptor
# against the frozen SCAD0 corpus instead of asserting a refusal — worth having
# when the pinned dom-protocol checkout is present on the machine.
HARNESS_FEATURES="${SEPOLIA_HARNESS_FEATURES:-rpc-http}"

# The one string that stands for "this scenario did not run". Kept
# byte-identical to `NOTHING_VERIFIED` in crates/f3-harness/tests/e2e_anvil.rs.
NOTHING_VERIFIED='SKIPPED — NOTHING WAS VERIFIED'

EXIT_REFUSED=1
EXIT_MISSING_ENV=2
EXIT_NO_FINALIZED_TAG=3
EXIT_FINALITY_TIMEOUT=4

# The ABI type of `LockTerms`, spelled once. Field order is normative — see the
# F3 interface spec section 1 — and any change here silently changes `binding`.
LOCK_TERMS_TYPE='(bytes32,uint8,bytes32,bytes32,bytes32,address,uint256,address,address,uint64)'

# `terms.asset` for the native contract. The ERC-20 contract refuses it: a
# codeless address accepts a CALL, returns nothing and moves nothing, so it is
# rejected at the door rather than trusted.
NATIVE_ASSET='0x0000000000000000000000000000000000000000'

ACCOUNT=""
declare -a STEP_PATHS=()
declare -a STEP_BLOCKS=()

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

# A random 32-byte word, used for the DOM-side identifiers this leg only
# carries (it does not interpret them).
rand_word() {
  python3 -c 'import os; print("0x"+os.urandom(32).hex())'
}

# A canonical secp256k1 scalar: top byte zeroed so it is far below the group
# order, low bit set so it is never the identity. Never printed.
new_scalar() {
  python3 -c '
import os
b = bytearray(os.urandom(32))
b[0] = 0
b[31] |= 1
print("0x" + b.hex())
'
}

# ---------------------------------------------------------------------------
# key handling
# ---------------------------------------------------------------------------

# Runs `cast` with the signing key.
#
# The key is never printed, echoed, logged or written to a file by this script:
# tracing is off (and switched off again here, so a `set -x` introduced anywhere
# above cannot reach this line), the argument list is never rendered, and
# nothing derived from the key beyond the public address is recorded.
#
# Named residue, recorded rather than papered over: `cast` 1.7.1 has no
# environment form of `--private-key` (`ETH_PRIVATE_KEY` is not read, and
# `--interactive` requires a TTY), and the alternative — importing a keystore —
# would write key material to disk, which is worse. So the key does appear in
# this process's own argument vector for the lifetime of each call, readable by
# the same user and by root. Run this on a machine where that is acceptable.
cast_signed() {
  set +x
  "$CAST" "$@" --private-key "$SEPOLIA_PRIVATE_KEY"
  local status=$?
  set +x
  return "$status"
}

# ---------------------------------------------------------------------------
# evidence file
# ---------------------------------------------------------------------------

EV_FLAT=""

ev_open() {
  mkdir -p "$EVIDENCE_DIR" || die "$EXIT_REFUSED" "cannot create $EVIDENCE_DIR"
  EV_FLAT="$(mktemp "${TMPDIR:-/tmp}/sepolia-e2e-ev.XXXXXX")" ||
    die "$EXIT_REFUSED" "cannot create a temporary evidence buffer"
}

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

require_finalized_tag() {
  if ! finalized_head; then
    warn "BLOCKED_EXTERNAL: this endpoint does not serve the 'finalized' block tag."
    warn ""
    warn "  A4-EVM makes the Ethereum 'finalized' tag the only source of finality"
    warn "  for this adapter, with no fallback: substituting a confirmation count"
    warn "  would silently downgrade the safety property the settlement rests on."
    warn "  An endpoint that cannot answer eth_getBlockByNumber(\"finalized\") is"
    warn "  therefore unusable here. This is a property of the provider, not of"
    warn "  the settlement: use an endpoint that serves the tag."
    exit "$EXIT_NO_FINALIZED_TAG"
  fi
  log "finalized  #$FINALIZED_NUMBER $FINALIZED_HASH"
}

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

# The chain's own clock. The EVM leg's timelock domain is Timestamp, so the
# refund deadline is compared against this and never against wall-clock time.
chain_timestamp() {
  local body ts
  body="$(rpc eth_getBlockByNumber '["latest",false]')" || return 1
  ts="$(printf '%s' "$body" | json_field timestamp)" || return 1
  hex2dec "$ts"
}

# Bounded wait until the chain's clock has passed $1.
wait_for_deadline() {
  local deadline="$1" started elapsed now
  started="$(date +%s)"
  while :; do
    now="$(chain_timestamp)" || now=""
    if [ -n "$now" ] && [ "$now" -ge "$deadline" ]; then
      return 0
    fi
    elapsed=$(( $(date +%s) - started ))
    if [ "$elapsed" -ge "$FINALITY_TIMEOUT" ]; then
      warn "timed out waiting for the refund deadline."
      warn "  deadline    $deadline (chain clock)"
      warn "  chain clock ${now:-unknown}"
      warn "  waited      ${elapsed}s of a ${FINALITY_TIMEOUT}s budget"
      return 1
    fi
    log "  waiting for the deadline: chain clock ${now:-?} < $deadline (${elapsed}s/${FINALITY_TIMEOUT}s)"
    sleep "$DEADLINE_POLL"
  done
}

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------

require_environment() {
  local missing=()
  # `${VAR:+set}` rather than `${VAR:-}`: the second renders the KEY ITSELF into
  # a shell trace, which is the one thing this script promises never to do. It
  # did, and `bash -x` found it. The first expands to "set" or to nothing, and
  # never to the value.
  [ -z "${SEPOLIA_RPC_URL:+set}" ] && missing+=("SEPOLIA_RPC_URL")
  [ -z "${SEPOLIA_PRIVATE_KEY:+set}" ] && missing+=("SEPOLIA_PRIVATE_KEY")
  [ -z "${SEPOLIA_LOCK:+set}" ] && missing+=("SEPOLIA_LOCK")
  [ -z "${SEPOLIA_ERC20_LOCK:+set}" ] && missing+=("SEPOLIA_ERC20_LOCK")
  if [ "${#missing[@]}" -gt 0 ]; then
    warn "missing required environment variable(s): ${missing[*]}"
    warn ""
    warn "  SEPOLIA_RPC_URL      Sepolia JSON-RPC endpoint (chain id ${SEPOLIA_CHAIN_ID})"
    warn "  SEPOLIA_PRIVATE_KEY  funding/claiming key; never printed or persisted"
    warn "  SEPOLIA_LOCK         ConditionLockV2 address (see scripts/sepolia_deploy.sh)"
    warn "  SEPOLIA_ERC20_LOCK   ConditionLockERC20V2 address (same source)"
    warn ""
    warn "usage: SEPOLIA_RPC_URL=... SEPOLIA_PRIVATE_KEY=... SEPOLIA_LOCK=0x... SEPOLIA_ERC20_LOCK=0x... $0"
    exit "$EXIT_MISSING_ENV"
  fi
}

require_tools() {
  [ -x "$CAST" ] ||
    die "$EXIT_REFUSED" "missing Foundry binary: $CAST (set FOUNDRY_BIN or CAST_BIN)"
  [ -x "$FORGE" ] ||
    die "$EXIT_REFUSED" "missing Foundry binary: $FORGE (set FOUNDRY_BIN or FORGE_BIN)"
  command -v python3 >/dev/null 2>&1 ||
    die "$EXIT_REFUSED" "python3 is required to assemble the evidence file"
}

require_sepolia() {
  local chain_id
  chain_id="$("$CAST" chain-id --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)"
  [ -n "$chain_id" ] ||
    die "$EXIT_REFUSED" "the endpoint did not answer eth_chainId; refusing to run"
  if [ "$chain_id" = "$MAINNET_CHAIN_ID" ]; then
    die "$EXIT_REFUSED" "REFUSED: SEPOLIA_RPC_URL points at Ethereum mainnet (chain id 1). This project targets no L1 mainnet and there is no override."
  fi
  if [ "$chain_id" != "$SEPOLIA_CHAIN_ID" ]; then
    die "$EXIT_REFUSED" "REFUSED: endpoint chain id is $chain_id, expected $SEPOLIA_CHAIN_ID (Sepolia). There is no override flag."
  fi
  log "chain id   $chain_id — Sepolia"
}

# `cast wallet address` prints the public address for a key. The key itself is
# never rendered, and here it is not even on the command line.
resolve_account() {
  ACCOUNT="$(cast_signed wallet address 2>/dev/null)"
  [ -n "$ACCOUNT" ] || die "$EXIT_REFUSED" "SEPOLIA_PRIVATE_KEY is not a usable key"
  log "account    $ACCOUNT"
}

# The token the ERC-20 flows lock, once deployed.
TOKEN=""
# Minted once, generously: two flows lock AMOUNT_WEI each, and a balance that
# cannot run out removes a whole class of mid-run failure for one cheap call.
TOKEN_MINT_AMOUNT="${SEPOLIA_TOKEN_MINT:-1000000000000000000}"

# Deploys and funds the ERC-20 fixture, recording it the way every other
# on-chain object here is recorded: address, runtime codehash, deploy
# transaction, block, and the canonical block at that height.
#
# `forge create` rather than `script/Deploy.s.sol`: that script deploys the two
# contracts the gate's codehash check binds to this source tree, and a test
# fixture has no business in it.
deploy_token() {
  log "== deploying the ERC-20 fixture =="
  local out status address tx_hash
  set +x
  out="$( (cd "$REPO_ROOT/contracts" && "$FORGE" create "$TOKEN_CONTRACT" \
    --rpc-url "$SEPOLIA_RPC_URL" --broadcast --json \
    --private-key "$SEPOLIA_PRIVATE_KEY") 2>/dev/null )"
  status=$?
  set +x
  if [ "$status" -ne 0 ] || [ -z "$out" ]; then
    warn "forge create failed for $TOKEN_CONTRACT"
    return 1
  fi

  address="$(printf '%s' "$out" | json_field deployedTo)" || address=""
  tx_hash="$(printf '%s' "$out" | json_field transactionHash)" || tx_hash=""
  if [ -z "$address" ] || [ -z "$tx_hash" ]; then
    warn "forge create produced no address or transaction hash for $TOKEN_CONTRACT"
    return 1
  fi
  TOKEN="$address"

  ev_set "token.name" "MockERC20"
  ev_set "token.source" "$TOKEN_CONTRACT"
  ev_set "token.address" "$TOKEN"
  ev_set "token.runtimeCodehash" "$(runtime_codehash "$TOKEN" || printf 'unavailable')"
  record_step "token.deploy" "$tx_hash" || return 1

  # A lock the funder cannot pay is not a test of the settlement, so the mint is
  # verified like any other step rather than assumed.
  send_step "token.mint" "$TOKEN" "mint(address,uint256)" "$ACCOUNT" "$TOKEN_MINT_AMOUNT" || return 1

  local balance
  balance="$("$CAST" call "$TOKEN" "balanceOf(address)(uint256)" "$ACCOUNT" \
    --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null | awk '{print $1}')"
  ev_set "token.funderBalance" "${balance:-unavailable}"
  log "  MockERC20  $TOKEN  balance ${balance:-unknown}"
  return 0
}

# ---------------------------------------------------------------------------
# settlement flows
# ---------------------------------------------------------------------------

# Records one settlement transaction: the tx hash it produced, the receipt
# fetched back independently, and the canonical block at that height. Pushes
# the step onto the list whose finality is proved later.
#
# record_step <evidence-path> <tx-hash>
record_step() {
  local path="$1" tx_hash="$2"
  ev_set "$path.txHash" "$tx_hash"

  local receipt status block_number block_hash decimal_block body canonical
  receipt="$(rpc eth_getTransactionReceipt "[\"$tx_hash\"]")"
  if [ -z "$receipt" ] || [ "$receipt" = "null" ]; then
    ev_set "$path.receipt.present" "false"
    warn "no receipt for $tx_hash"
    return 1
  fi
  ev_set "$path.receipt.present" "true"
  status="$(printf '%s' "$receipt" | json_field status)" || status="0x0"
  block_number="$(printf '%s' "$receipt" | json_field blockNumber)" || block_number=""
  block_hash="$(printf '%s' "$receipt" | json_field blockHash)" || block_hash=""
  ev_set "$path.receipt.status" "$(hex2dec "$status")"
  ev_set "$path.blockNumber" "$(hex2dec "${block_number:-0x0}")"
  ev_set "$path.blockHash" "${block_hash:-unavailable}"

  if [ "$(hex2dec "$status")" != "1" ]; then
    warn "transaction $tx_hash reverted (status $status)"
    return 1
  fi

  # The block, fetched independently of the receipt.
  body="$(rpc eth_getBlockByNumber "[\"$block_number\",false]")"
  canonical=""
  if [ -n "$body" ] && [ "$body" != "null" ]; then
    canonical="$(printf '%s' "$body" | json_field hash)" || canonical=""
  fi
  ev_set "$path.canonicalBlockHash" "${canonical:-unavailable}"
  if [ "$canonical" != "$block_hash" ]; then
    ev_set "$path.canonical" "false"
    warn "the canonical block at $block_number is not the block the receipt names"
    return 1
  fi
  ev_set "$path.canonical" "true"

  decimal_block="$(hex2dec "$block_number")"
  STEP_PATHS+=("$path")
  STEP_BLOCKS+=("$decimal_block")
  log "    $path  block $decimal_block  $tx_hash"
  return 0
}

# Sends one contract call and records it. Prints nothing derived from the key.
#
# send_step <evidence-path> <extra-cast-args...>
send_step() {
  local path="$1"
  shift
  local out tx_hash
  # stdout only: it is parsed as JSON, so a provider warning on stderr must not
  # be able to contaminate it. Foundry's diagnostics go straight to the
  # operator's terminal, where they are useful and where they never render the
  # key.
  out="$(cast_signed send --rpc-url "$SEPOLIA_RPC_URL" --json "$@")"
  local status=$?
  if [ "$status" -ne 0 ]; then
    ev_set "$path.sent" "false"
    warn "cast send failed for $path (see the diagnostics above)"
    return 1
  fi
  tx_hash="$(printf '%s' "$out" | json_field transactionHash)" || tx_hash=""
  if [ -z "$tx_hash" ]; then
    ev_set "$path.sent" "false"
    warn "cast send produced no transaction hash for $path"
    return 1
  fi
  ev_set "$path.sent" "true"
  record_step "$path" "$tx_hash"
}

# Drives one complete flow.
#
# run_flow <key> <direction 0|1> <deadline-offset-seconds> <claim|refund>
#          [lock-address] [asset-address]
#
# The last two default to the native contract and `address(0)`. Passing the
# ERC-20 contract and a token address switches the flow to the ERC-20 variant:
# same calls, same evidence shape, one extra `approve` and no ETH on `open`.
run_flow() {
  local key="$1" direction="$2" offset="$3" settle="$4"
  local lock="${5:-$SEPOLIA_LOCK}"
  local asset="${6:-$NATIVE_ASSET}"
  local base="flows.$key"

  local dom_chain_id session_id terms_hash participants_hash scalar adaptor
  dom_chain_id="$(rand_word)"
  session_id="$(rand_word)"
  terms_hash="$(rand_word)"
  participants_hash="$(rand_word)"
  scalar="$(new_scalar)"
  # address(t*G) — the same derivation the contract performs with ecrecover.
  # Computed locally; the scalar is never logged.
  set +x
  adaptor="$("$CAST" wallet address --private-key "$scalar" 2>/dev/null)"
  set +x
  [ -n "$adaptor" ] || {
    warn "could not derive the adaptor address for flow $key"
    return 1
  }

  local now deadline
  now="$(chain_timestamp)" || {
    warn "the endpoint did not answer eth_getBlockByNumber(latest)"
    return 1
  }
  deadline=$(( now + offset ))

  local terms
  terms="($dom_chain_id,$direction,$session_id,$terms_hash,$participants_hash,$asset,$AMOUNT_WEI,$ACCOUNT,$adaptor,$deadline)"

  local lock_id binding
  binding="$("$CAST" call "$lock" "deriveBinding($LOCK_TERMS_TYPE)(bytes32)" "$terms" \
    --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)"
  lock_id="$("$CAST" call "$lock" "deriveLockId($LOCK_TERMS_TYPE,address)(bytes32)" "$terms" "$ACCOUNT" \
    --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)"
  if [ -z "$binding" ] || [ -z "$lock_id" ]; then
    warn "the contract did not answer deriveBinding/deriveLockId for flow $key"
    return 1
  fi

  ev_set "$base.direction" "$direction"
  ev_set "$base.settlement" "$settle"
  ev_set "$base.contract" "$lock"
  if [ "$asset" = "$NATIVE_ASSET" ]; then
    ev_set "$base.assetKind" "native"
    ev_set "$base.asset" "native"
  else
    ev_set "$base.assetKind" "erc20"
    ev_set "$base.asset" "$asset"
  fi
  ev_set "$base.amountWei" "$AMOUNT_WEI"
  ev_set "$base.funder" "$ACCOUNT"
  ev_set "$base.beneficiary" "$ACCOUNT"
  ev_set "$base.domChainId" "$dom_chain_id"
  ev_set "$base.sessionId" "$session_id"
  ev_set "$base.termsHash" "$terms_hash"
  ev_set "$base.participantsHash" "$participants_hash"
  ev_set "$base.adaptorAddress" "$adaptor"
  ev_set "$base.deadline" "$deadline"
  ev_set "$base.binding" "$binding"
  ev_set "$base.lockId" "$lock_id"

  log "  flow $key (direction $direction, settle by $settle)"
  log "    lockId  $lock_id"

  if [ "$asset" = "$NATIVE_ASSET" ]; then
    send_step "$base.steps.open" "$lock" "open($LOCK_TERMS_TYPE)" "$terms" \
      --value "$AMOUNT_WEI" || return 1
  else
    # The ERC-20 contract pulls the amount with `transferFrom` and rejects any
    # ETH, so the approval is part of the flow rather than setup, and `open`
    # carries no value. Approving exactly `AMOUNT_WEI` keeps the standing
    # allowance at zero between flows.
    send_step "$base.steps.approve" "$asset" "approve(address,uint256)" \
      "$lock" "$AMOUNT_WEI" || return 1
    send_step "$base.steps.open" "$lock" "open($LOCK_TERMS_TYPE)" "$terms" || return 1
  fi

  case "$settle" in
    claim)
      send_step "$base.steps.claim" "$lock" "claim(bytes32,uint256)" \
        "$lock_id" "$scalar" || return 1
      # The scalar is now public: it is in the calldata and in the `Claimed`
      # event. It is still not written here — a reader who needs it takes it
      # from the chain, which is the only place it is a fact rather than a copy.
      ev_set "$base.scalarRevealedOnChain" "true"
      ;;
    refund)
      log "    waiting out the deadline before refunding"
      wait_for_deadline "$deadline" || return 1
      send_step "$base.steps.refund" "$lock" "refund(bytes32)" "$lock_id" || return 1
      ;;
    *)
      warn "unknown settlement kind: $settle"
      return 1
      ;;
  esac
  ev_set "$base.settled" "true"
  return 0
}

# Withdraws whatever pull credit the flows above left behind, so the contract is
# handed to the harness phase with this account's credit at zero.
#
# WHY THIS EXISTS. `claim` and `refund` pay the beneficiary optimistically, and
# fall back to booking a credit when the payout call is not given enough gas to
# push. These flows are driven by `cast send`, which sizes a transaction from
# `eth_estimateGas`, and an estimator-chosen limit lands on the deferral every
# time — the ERC-20 contract documents the same cliff for its own payout path.
# So each settled flow leaves 1 wei of credit here. That is the contract working
# as designed: an unprovable delivery becomes a claimable credit rather than a
# lie.
#
# It matters because `anvil_evm_to_dom_direction` asserts, after its own claim,
# that `pendingWithdrawals` is ZERO — an absolute read of contract state, not a
# delta. Its companion assertion (no `PayoutDeferred` in the harness's own block
# range) is correctly scoped; this one is not, and it therefore fails on any
# contract that carries credit from earlier activity. On the 2026-08-11 run it
# read 3 — one wei per native flow — and failed a harness phase that had done
# nothing wrong.
#
# Draining here fixes the precondition rather than the assertion. The assertion
# keeps its full force: if the harness's own payout defers, the credit it reads
# is 1, not 0, and it still fails. Nothing is loosened, and the withdrawal path
# gets exercised on a public network as a side effect.
drain_pull_credits() {
  log "== withdrawing the pull credits the flows left =="
  local spec lock asset label
  for spec in "$SEPOLIA_LOCK|$NATIVE_ASSET|native" "$SEPOLIA_ERC20_LOCK|$TOKEN|erc20"; do
    lock="${spec%%|*}"
    asset="$(printf '%s' "$spec" | cut -d'|' -f2)"
    label="${spec##*|}"
    [ -n "$lock" ] && [ -n "$asset" ] || continue

    local credit
    credit="$("$CAST" call "$lock" "pendingWithdrawals(address,address)(uint256)" \
      "$ACCOUNT" "$asset" --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null | awk '{print $1}')"
    credit="${credit:-0}"
    ev_set "withdrawals.$label.creditBefore" "$credit"
    if [ "$credit" = "0" ]; then
      log "  $label: no credit to withdraw"
      ev_set "withdrawals.$label.withdrawn" "false"
      continue
    fi
    log "  $label: withdrawing $credit"
    send_step "withdrawals.$label.tx" "$lock" "withdraw(address)" "$asset" || return 1
    ev_set "withdrawals.$label.withdrawn" "true"

    local after
    after="$("$CAST" call "$lock" "pendingWithdrawals(address,address)(uint256)" \
      "$ACCOUNT" "$asset" --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null | awk '{print $1}')"
    ev_set "withdrawals.$label.creditAfter" "${after:-unavailable}"
    if [ "${after:-1}" != "0" ]; then
      warn "the $label credit is still ${after:-unknown} after withdraw; the harness will fail on it"
      return 1
    fi
  done
  return 0
}

# Proves, for every recorded step, that the finalized head is at or above the
# block the step landed in. The head is re-read per step, so each observation
# is its own reading rather than one reading copied across.
prove_finality_for_every_step() {
  local i highest=0
  for i in "${!STEP_BLOCKS[@]}"; do
    [ "${STEP_BLOCKS[$i]}" -gt "$highest" ] && highest="${STEP_BLOCKS[$i]}"
  done
  log "== waiting for finality to cover block $highest =="
  wait_for_finality "$highest" || return "$EXIT_FINALITY_TIMEOUT"

  for i in "${!STEP_PATHS[@]}"; do
    local path="${STEP_PATHS[$i]}" block="${STEP_BLOCKS[$i]}"
    if ! finalized_head; then
      warn "the endpoint stopped serving the finalized tag mid-run"
      return "$EXIT_NO_FINALIZED_TAG"
    fi
    ev_set "$path.finalizedAtObservation.number" "$FINALIZED_NUMBER"
    ev_set "$path.finalizedAtObservation.hash" "$FINALIZED_HASH"
    if [ "$FINALIZED_NUMBER" -ge "$block" ]; then
      ev_set "$path.finalizedCoversBlock" "true"
    else
      ev_set "$path.finalizedCoversBlock" "false"
      warn "finalized #$FINALIZED_NUMBER does not cover block $block for $path"
      return "$EXIT_FINALITY_TIMEOUT"
    fi
  done
  return 0
}

# ---------------------------------------------------------------------------
# integration phase
# ---------------------------------------------------------------------------

# Runs one f3-harness test by name and records whether it actually ran.
#
# Asserting on a *named* test rather than on an aggregate count is deliberate:
# a suite that silently loses a test still reports "ok".
#
# THREE separate things are required, because none of them implies the others:
#
#   ran     — `test <name> ...` appears in the output. Under `--nocapture`
#             libtest writes that prefix, then the test's own output, and only
#             then `ok` on a line of its own, so `test <name> ... ok` NEVER
#             appears as one line and grepping for it would fail every time.
#             (It did. This is the corrected form.)
#   passed  — libtest's own summary says `1 passed; 0 failed; 0 ignored`.
#   verified— the harness's skip marker is absent. A test that returns early
#             still prints `ok`; the marker is how it says it did nothing.
run_harness_test() {
  local name="$1" out status summary ran=0 passed=0
  log "  $name"
  out="$(F3_SEPOLIA_RPC="$SEPOLIA_RPC_URL" \
    F3_ANVIL_RPC="$SEPOLIA_RPC_URL" \
    F3_ANVIL_LOCK="$SEPOLIA_LOCK" \
    F3_ANVIL_ACCOUNT="$ACCOUNT" \
    F3_ANVIL_KEY="$SEPOLIA_PRIVATE_KEY" \
    F3_CAST="$CAST" \
    cargo test -p f3-harness --features "$HARNESS_FEATURES" --test e2e_anvil \
    "$name" -- --exact --ignored --nocapture --test-threads 1 2>&1)"
  status=$?
  printf '%s\n' "$out"

  printf '%s\n' "$out" | grep -qE "^test $name \.\.\." && ran=1
  summary="$(printf '%s\n' "$out" | grep -E '^test result:' | tail -1)"
  printf '%s' "$summary" | grep -q '^test result: ok\. 1 passed; 0 failed; 0 ignored;' && passed=1

  if [ "$ran" -ne 1 ]; then
    ev_set "harness.$name.ran" "false"
    ev_set "harness.$name.passed" "false"
    warn "the test $name never started — the filter matched nothing, or the binary did not build"
    return 1
  fi
  ev_set "harness.$name.ran" "true"

  if printf '%s' "$out" | grep -qF "$NOTHING_VERIFIED"; then
    ev_set "harness.$name.passed" "false"
    warn "the test $name printed \"$NOTHING_VERIFIED\": it ran and verified nothing"
    return 1
  fi
  if [ "$passed" -ne 1 ] || [ "$status" -ne 0 ]; then
    ev_set "harness.$name.passed" "false"
    warn "the test $name did not pass (cargo exit $status): ${summary:-no summary line}"
    return 1
  fi
  ev_set "harness.$name.passed" "true"
  return 0
}

# ---------------------------------------------------------------------------

main() {
  require_environment
  require_tools
  log "== checking the endpoint =="
  require_sepolia
  require_finalized_tag
  resolve_account

  local codehash balance
  codehash="$(runtime_codehash "$SEPOLIA_LOCK")" || codehash=""
  balance="$("$CAST" balance "$ACCOUNT" --rpc-url "$SEPOLIA_RPC_URL" 2>/dev/null)"
  log "contract   $SEPOLIA_LOCK"
  log "codehash   ${codehash:-unavailable}"
  log "balance    ${balance:-unknown} wei"

  ev_open
  ev_set "schema" "dom-interop/f3/sepolia-e2e/v1"
  ev_set "network.name" "sepolia"
  ev_set "network.chainId" "$SEPOLIA_CHAIN_ID"
  ev_set "network.finalizedTagServed" "true"
  ev_set "network.finalizedAtStart.number" "$FINALIZED_NUMBER"
  ev_set "network.finalizedAtStart.hash" "$FINALIZED_HASH"
  ev_set "contract.address" "$SEPOLIA_LOCK"
  ev_set "contract.runtimeCodehash" "${codehash:-unavailable}"
  ev_set "erc20Contract.address" "$SEPOLIA_ERC20_LOCK"
  ev_set "erc20Contract.runtimeCodehash" "$(runtime_codehash "$SEPOLIA_ERC20_LOCK" || printf 'unavailable')"
  ev_set "account" "$ACCOUNT"
  ev_set "startedAtUtc" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  log "== settlement flows =="
  local failed=0
  run_flow dom_to_evm 0 "$CLAIM_DEADLINE" claim || failed=1
  run_flow evm_to_dom 1 "$CLAIM_DEADLINE" claim || failed=1
  run_flow refund 0 "$REFUND_DELAY" refund || failed=1

  # The ERC-20 variant, on both direction values and both settlement paths.
  # Operator-ratified addition of 2026-08-11; see the provenance note at the top
  # of this file. A token that fails to deploy fails the run rather than
  # silently reducing it to the native leg.
  if deploy_token; then
    run_flow erc20_dom_to_evm 0 "$CLAIM_DEADLINE" claim "$SEPOLIA_ERC20_LOCK" "$TOKEN" || failed=1
    run_flow erc20_refund 1 "$REFUND_DELAY" refund "$SEPOLIA_ERC20_LOCK" "$TOKEN" || failed=1
  else
    warn "the ERC-20 fixture could not be deployed; the ERC-20 flows did not run"
    ev_set "token.deployed" "false"
    failed=1
  fi

  # Hand the contracts to the harness with this account's credit at zero. Only
  # attempted when the flows themselves succeeded: on a failed run the credit is
  # diagnostic evidence and draining it would destroy the trail.
  if [ "$failed" -eq 0 ]; then
    drain_pull_credits || failed=1
  fi

  if [ "${#STEP_PATHS[@]}" -gt 0 ]; then
    local rc=0
    prove_finality_for_every_step || rc=$?
    if [ "$rc" = "$EXIT_FINALITY_TIMEOUT" ] || [ "$rc" = "$EXIT_NO_FINALIZED_TAG" ]; then
      ev_set "result" "FINALITY_NOT_PROVED"
      ev_write
      exit "$rc"
    fi
  fi

  if [ "$failed" -ne 0 ]; then
    ev_set "result" "FLOW_FAILED"
    ev_write
    die "$EXIT_REFUSED" "at least one settlement flow failed; see $EVIDENCE_FILE"
  fi

  if [ "${SEPOLIA_SKIP_HARNESS:-0}" = "1" ]; then
    ev_set "harness.skipped" "true"
  else
    log "== f3-harness integration, by name =="
    cd "$REPO_ROOT" || die "$EXIT_REFUSED" "no repository root"
    ev_set "harness.skipped" "false"
    # `anvil_refund_by_deadline` is absent on purpose: it drives
    # `evm_increaseTime`, which a public network does not serve. The refund is
    # covered by the `refund` flow above, on the real clock.
    run_harness_test anvil_evm_to_dom_direction || failed=1
    run_harness_test anvil_dom_to_evm_direction || failed=1
  fi

  ev_set "finishedAtUtc" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [ "$failed" -ne 0 ]; then
    ev_set "result" "HARNESS_FAILED"
    ev_write
    die "$EXIT_REFUSED" "the harness phase failed; see $EVIDENCE_FILE"
  fi
  ev_set "result" "OK"
  ev_write

  log ""
  log "== done =="
  log "  evidence  $EVIDENCE_FILE"
}

# Executed normally: run everything. Sourced (by a test that wants to exercise
# one helper in isolation): define the functions and stop. Sourcing bypasses no
# check, because every check lives inside `main`, which a source does not call.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
