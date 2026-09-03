#!/usr/bin/env bash
# Stage 9 — integrated local deployment: Anvil + Bitcoin regtest + two DOM
# nodes, with every deployment fact recorded into one machine-readable mold.
#
# This is the roadmap's point 3: one command brings up the three execution
# environments the composed route needs, deploys the real lock contracts,
# and writes deploy-local-manifest.v1.json — the mold the production_config
# generator consumes. Nothing here is mocked: the contracts are the compiled
# ConditionLock artifacts, the Bitcoin chain is a real bitcoind, and the DOM
# chain is two real dom-node processes peered with each other.
#
# Fail-closed discipline:
#   * every service must prove liveness (bounded polls, never sleep-and-hope);
#   * every recorded fact is read back from the running service, not assumed;
#   * teardown kills everything unless KEEP=1 (stage 10 uses KEEP=1).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${DEPLOY_LOCAL_DIR:-$ROOT/testnet/local-deploy}"
MANIFEST="$OUT_DIR/deploy-local-manifest.v1.json"
KEEP="${KEEP:-0}"

ANVIL_PORT="${ANVIL_PORT:-8545}"
ANVIL_RPC="http://127.0.0.1:${ANVIL_PORT}"
# Anvil's first funded dev key (public, dev-only).
ANVIL_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
BTC_RPC_PORT="${BTC_RPC_PORT:-18443}"
DOM_A_P2P="${DOM_A_P2P:-127.0.0.1:34401}"
DOM_A_RPC="${DOM_A_RPC:-127.0.0.1:34402}"
DOM_B_P2P="${DOM_B_P2P:-127.0.0.1:34411}"
DOM_B_RPC="${DOM_B_RPC:-127.0.0.1:34412}"

CAST="${CAST:-cast}"
FORGE="${FORGE:-forge}"
for tool in "$CAST" "$FORGE" anvil bitcoind bitcoin-cli curl python3; do
  command -v "$tool" >/dev/null || { echo "required tool missing: $tool" >&2; exit 1; }
done

mkdir -p "$OUT_DIR"
PIDS=()
cleanup() {
  if [ "$KEEP" = "1" ]; then
    echo "== KEEP=1: services left running (pids: ${PIDS[*]:-none}) =="
    return
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

poll() { # poll <what> <tries> <cmd...>
  local what="$1" tries="$2"; shift 2
  local i=0
  while [ "$i" -lt "$tries" ]; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    i=$((i + 1))
  done
  echo "liveness failed: $what" >&2
  return 1
}

# ---------------------------------------------------------------- 1. Anvil
echo "== [1/4] anvil on $ANVIL_RPC =="
anvil --port "$ANVIL_PORT" --silent > "$OUT_DIR/anvil.log" 2>&1 &
PIDS+=("$!")
poll "anvil rpc" 600 "$CAST" chain-id --rpc-url "$ANVIL_RPC"
EVM_CHAIN_ID="$("$CAST" chain-id --rpc-url "$ANVIL_RPC")"
EVM_GENESIS="$("$CAST" block 0 --rpc-url "$ANVIL_RPC" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["hash"])')"

echo "== [1/4] deploying lock contracts =="
( cd "$ROOT/contracts" && EXPECTED_CHAIN_ID="$EVM_CHAIN_ID" "$FORGE" script script/Deploy.s.sol \
    --rpc-url "$ANVIL_RPC" --broadcast --private-key "$ANVIL_KEY" ) > "$OUT_DIR/deploy.log" 2>&1
RUN_JSON="$ROOT/contracts/broadcast/Deploy.s.sol/${EVM_CHAIN_ID}/run-latest.json"
NATIVE_LOCK="$(python3 -c "
import json;d=json.load(open('$RUN_JSON'))
print(next(t['contractAddress'] for t in d['transactions'] if t.get('contractName')=='ConditionLockV2'))")"
ERC20_LOCK="$(python3 -c "
import json;d=json.load(open('$RUN_JSON'))
print(next(t['contractAddress'] for t in d['transactions'] if t.get('contractName')=='ConditionLockERC20V2'))")"
NATIVE_CODEHASH="$("$CAST" keccak "$("$CAST" code "$NATIVE_LOCK" --rpc-url "$ANVIL_RPC")")"
ERC20_CODEHASH="$("$CAST" keccak "$("$CAST" code "$ERC20_LOCK" --rpc-url "$ANVIL_RPC")")"
EVM_DEPLOY_BLOCK="$("$CAST" block-number --rpc-url "$ANVIL_RPC")"
[ "$NATIVE_CODEHASH" != "0x" ] && [ "$ERC20_CODEHASH" != "0x" ] || { echo "empty runtime code" >&2; exit 1; }

# ------------------------------------------------------- 2. Bitcoin regtest
echo "== [2/4] bitcoind regtest on rpc port $BTC_RPC_PORT =="
BTC_DATADIR="$OUT_DIR/btc-regtest"
rm -rf "$BTC_DATADIR"; mkdir -p "$BTC_DATADIR"
bitcoind -regtest -datadir="$BTC_DATADIR" -rpcport="$BTC_RPC_PORT" \
  -fallbackfee=0.0001 -daemonwait > "$OUT_DIR/bitcoind.log" 2>&1
PIDS+=("$(cat "$BTC_DATADIR/regtest/bitcoind.pid")")
BCLI=(bitcoin-cli -regtest -datadir="$BTC_DATADIR" -rpcport="$BTC_RPC_PORT")
"${BCLI[@]}" createwallet dom-local >/dev/null
MINE_ADDR="$("${BCLI[@]}" getnewaddress)"
"${BCLI[@]}" generatetoaddress 101 "$MINE_ADDR" >/dev/null
BTC_GENESIS="$("${BCLI[@]}" getblockhash 0)"
BTC_HEIGHT="$("${BCLI[@]}" getblockcount)"
BTC_BALANCE="$("${BCLI[@]}" getbalance)"

# ------------------------------------------------------------ 3. DOM nodes
echo "== [3/4] two dom-node regtest peers =="
DOM_NODE="$ROOT/target/debug/dom-node"
if [ ! -x "$DOM_NODE" ]; then
  ( cd "$ROOT" && cargo build -p dom-node --bin dom-node ) > "$OUT_DIR/dom-node-build.log" 2>&1
fi
rm -rf "$OUT_DIR/dom-a" "$OUT_DIR/dom-b"; mkdir -p "$OUT_DIR/dom-a" "$OUT_DIR/dom-b"
DOM_NETWORK=regtest DOM_DATA_DIR="$OUT_DIR/dom-a" DOM_MINE=1 \
  DOM_P2P_LISTEN_ADDR="$DOM_A_P2P" DOM_RPC_LISTEN_ADDR="$DOM_A_RPC" \
  "$DOM_NODE" > "$OUT_DIR/dom-a.log" 2>&1 &
PIDS+=("$!")
DOM_NETWORK=regtest DOM_DATA_DIR="$OUT_DIR/dom-b" \
  DOM_P2P_LISTEN_ADDR="$DOM_B_P2P" DOM_RPC_LISTEN_ADDR="$DOM_B_RPC" \
  DOM_SEED_PEERS="$DOM_A_P2P" \
  "$DOM_NODE" > "$OUT_DIR/dom-b.log" 2>&1 &
PIDS+=("$!")
poll "dom-node A rpc" 600 curl -fsS "http://$DOM_A_RPC/status"
poll "dom-node B rpc" 600 curl -fsS "http://$DOM_B_RPC/status"
DOM_IDENTITY="$(curl -fsS "http://$DOM_A_RPC/chain/identity")"
DOM_IDENTITY_B="$(curl -fsS "http://$DOM_B_RPC/chain/identity")"
if [ "$DOM_IDENTITY" != "$DOM_IDENTITY_B" ]; then
  echo "the two DOM nodes disagree on chain identity: refusing to record" >&2
  exit 1
fi

# -------------------------------------------------------------- 4. Manifest
echo "== [4/4] recording the deployment mold =="
SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
python3 - "$MANIFEST" <<PY
import json, sys
json.dump({
  "version": 1,
  "source_commit": "$SOURCE_COMMIT",
  "evm": {
    "rpc": "$ANVIL_RPC",
    "chain_id": $EVM_CHAIN_ID,
    "genesis_hash": "$EVM_GENESIS",
    "native_lock": "$NATIVE_LOCK",
    "native_runtime_codehash": "$NATIVE_CODEHASH",
    "erc20_lock": "$ERC20_LOCK",
    "erc20_runtime_codehash": "$ERC20_CODEHASH",
    "deploy_block": $EVM_DEPLOY_BLOCK,
    "native_decimals": 18
  },
  "bitcoin": {
    "network": "regtest",
    "rpc_port": $BTC_RPC_PORT,
    "datadir": "$BTC_DATADIR",
    "wallet": "dom-local",
    "genesis_hash": "$BTC_GENESIS",
    "height": $BTC_HEIGHT,
    "spendable_btc": "$BTC_BALANCE"
  },
  "dom": {
    "network": "regtest",
    "node_a": {"p2p": "$DOM_A_P2P", "rpc": "http://$DOM_A_RPC", "mining": True},
    "node_b": {"p2p": "$DOM_B_P2P", "rpc": "http://$DOM_B_RPC", "mining": False},
    "chain_identity": json.loads(r'''$DOM_IDENTITY''')
  }
}, open(sys.argv[1], "w"), indent=2)
PY
echo "mold recorded: $MANIFEST"
python3 -m json.tool "$MANIFEST" >/dev/null && echo "manifest is valid JSON"
if [ "$KEEP" = "1" ]; then
  echo "environments left running for stage-10 use"
fi
