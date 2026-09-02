#!/usr/bin/env bash
# Sepolia — deploys both ConditionLock contracts and records the deploy facts.
#
# RECONSTRUCTION (2026-09-02): rebuilt over contracts/script/Deploy.s.sol and
# the e2e_anvil.sh deploy path; never existed in this repository before.
#
# Produces contracts/release/sepolia-deploy.<unix-ts>.json with every fact the
# deployment registry needs: chain id, addresses, runtime codehashes, deploy
# block, and the exact commit of this tree.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
source "$ROOT/scripts/sepolia.sh"

FORGE="${FORGE:-forge}"
cd "$ROOT/contracts"

echo "== deploying ConditionLockV2 + ConditionLockERC20V2 to Sepolia =="
EXPECTED_CHAIN_ID="$SEPOLIA_CHAIN_ID" "$FORGE" script script/Deploy.s.sol \
  --rpc-url "$SEPOLIA_RPC_URL" --broadcast --private-key "$SEPOLIA_PRIVATE_KEY"

RUN_JSON="broadcast/Deploy.s.sol/${SEPOLIA_CHAIN_ID}/run-latest.json"
[ -f "$RUN_JSON" ] || { echo "forge broadcast record missing: $RUN_JSON" >&2; exit 1; }
NATIVE_LOCK="$(python3 -c "
import json;d=json.load(open('$RUN_JSON'))
print(next(t['contractAddress'] for t in d['transactions'] if t.get('contractName')=='ConditionLockV2'))")"
ERC20_LOCK="$(python3 -c "
import json;d=json.load(open('$RUN_JSON'))
print(next(t['contractAddress'] for t in d['transactions'] if t.get('contractName')=='ConditionLockERC20V2'))")"
BLOCK="$("$CAST" block-number --rpc-url "$SEPOLIA_RPC_URL")"
NATIVE_CODEHASH="$("$CAST" keccak "$("$CAST" code "$NATIVE_LOCK" --rpc-url "$SEPOLIA_RPC_URL")")"
ERC20_CODEHASH="$("$CAST" keccak "$("$CAST" code "$ERC20_LOCK" --rpc-url "$SEPOLIA_RPC_URL")")"
[ "$NATIVE_CODEHASH" != "0x" ] && [ "$ERC20_CODEHASH" != "0x" ] || {
  echo "deployed code unreadable: refusing to record" >&2; exit 1; }

OUT="$ROOT/contracts/release/sepolia-deploy.$(date +%s).json"
python3 - "$OUT" <<PY
import json, subprocess, sys
commit = subprocess.run(["git","-C","$ROOT","rev-parse","HEAD"],capture_output=True,text=True).stdout.strip()
json.dump({
  "network":"sepolia","chain_id":$SEPOLIA_CHAIN_ID,
  "native_lock":"$NATIVE_LOCK","native_runtime_codehash":"$NATIVE_CODEHASH",
  "erc20_lock":"$ERC20_LOCK","erc20_runtime_codehash":"$ERC20_CODEHASH",
  "deploy_block":$BLOCK,"deployer":"$SEPOLIA_ACCOUNT","source_commit":commit,
}, open(sys.argv[1],"w"), indent=2)
PY
echo "deploy facts recorded: $OUT"
