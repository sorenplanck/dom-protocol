#!/usr/bin/env bash
# F5 local Regtest end-to-end with the genesis-rooted btc-evidence V2 gate.
#
# This script starts only a throwaway Bitcoin Core Regtest node. It does not
# start or contact Signet. Each terminal transaction is included in a complete
# block, followed by one successor (depth two), then verified through the V2
# Regtest header authority before its outcome is allowed to cross the USPE
# bridge.
set -euo pipefail
umask 077

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
REGTEST_DATADIR="$(mktemp -d)"
RPCPORT="${RPCPORT:-18443}"
CLI=(bitcoin-cli -regtest -datadir="$REGTEST_DATADIR" -rpcport="$RPCPORT")
WCLI=("${CLI[@]}" -rpcwallet=e2e)
CSV_BLOCKS=144
FEE_SAT=2000
MINIMUM_DEPTH=2
AUTHORITY_ROOT="$REGTEST_DATADIR/regtest-authority-v2"
AUTHORITY_INPUT="$REGTEST_DATADIR/regtest-authority-input-v2.json"
OBSERVER_STATE="$REGTEST_DATADIR/regtest-observer-state-v2"

cleanup() {
  "${CLI[@]}" stop >/dev/null 2>&1 || true
  if [[ -n "$REGTEST_DATADIR" && -d "$REGTEST_DATADIR" && "$REGTEST_DATADIR" == /tmp/* ]]; then
    rm -rf -- "$REGTEST_DATADIR"
  fi
}
trap cleanup EXIT

btc() { "${CLI[@]}" "$@"; }
wbtc() { "${WCLI[@]}" "$@"; }
cargo_f5() {
  cargo run --quiet --locked --manifest-path "$REPO_ROOT/Cargo.toml" -p f5-e2e -- "$@"
}

write_regtest_authority_input() {
  local checkpoint_height="$1"
  local output_path="$2"

  python3 - "$REGTEST_DATADIR" "$RPCPORT" "$MINIMUM_DEPTH" \
    "$checkpoint_height" "$output_path" <<'PY'
import json
import subprocess
import sys

datadir, rpcport, minimum_depth, checkpoint_height, output_path = sys.argv[1:]
cli = ["bitcoin-cli", "-regtest", f"-datadir={datadir}", f"-rpcport={rpcport}"]

def rpc(*arguments):
    return subprocess.check_output([*cli, *map(str, arguments)], text=True).strip()

def header_at(height):
    block_hash = rpc("getblockhash", height)
    return {
        "height": height,
        "hash": block_hash,
        "header": rpc("getblockheader", block_hash, "false"),
    }

checkpoint_height = int(checkpoint_height)
authority = {
    "schema": "dom-f5-regtest-authority-v2",
    "minimum_confirmation_depth": int(minimum_depth),
    "checkpoint_headers": [
        header_at(height) for height in range(0, checkpoint_height + 1)
    ],
}
with open(output_path, "x", encoding="ascii", newline="\n") as handle:
    json.dump(authority, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
}

write_regtest_v2_evidence() {
  local outcome="$1"
  local terminal_txid="$2"
  local settlement_id="$3"
  local terms_hash="$4"
  local funding_txid="$5"
  local funding_vout="$6"
  local checkpoint_height="$7"
  local output_path="$8"

  python3 - "$REGTEST_DATADIR" "$RPCPORT" "$outcome" "$terminal_txid" \
    "$settlement_id" "$terms_hash" "$funding_txid" "$funding_vout" \
    "$MINIMUM_DEPTH" "$checkpoint_height" "$output_path" <<'PY'
import json
import subprocess
import sys

(
    datadir,
    rpcport,
    outcome,
    terminal_txid,
    settlement_id,
    terms_hash,
    funding_txid,
    funding_vout,
    minimum_depth,
    checkpoint_height,
    output_path,
) = sys.argv[1:]

cli = ["bitcoin-cli", "-regtest", f"-datadir={datadir}", f"-rpcport={rpcport}"]

def rpc(*arguments):
    return subprocess.check_output([*cli, *map(str, arguments)], text=True).strip()

def header_at(height):
    block_hash = rpc("getblockhash", height)
    return {
        "height": height,
        "hash": block_hash,
        "header": rpc("getblockheader", block_hash, "false"),
    }

transaction = json.loads(rpc("getrawtransaction", terminal_txid, "true"))
block_hash = transaction.get("blockhash")
if not isinstance(block_hash, str):
    raise SystemExit("terminal transaction is not in a canonical block")
block_header = json.loads(rpc("getblockheader", block_hash, "true"))
block_height = block_header.get("height")
if not isinstance(block_height, int) or block_height < 1:
    raise SystemExit("invalid containing block height")
tip_height = int(rpc("getblockcount"))
checkpoint_height = int(checkpoint_height)
if checkpoint_height < 0 or block_height <= checkpoint_height:
    raise SystemExit("terminal block is not after the pinned authority checkpoint")
if tip_height - block_height + 1 < int(minimum_depth):
    raise SystemExit("terminal transaction is below the V2 confirmation policy")

block = json.loads(rpc("getblock", block_hash, "1"))
transactions = block.get("tx")
if not isinstance(transactions, list) or terminal_txid not in transactions:
    raise SystemExit("terminal transaction is absent from the complete block index")

evidence = {
    "schema": "dom-f5-regtest-evidence-v2",
    "network_kind": "bitcoin-regtest-v2",
    "network_genesis": rpc("getblockhash", 0),
    "settlement_id": settlement_id,
    "terms_hash": terms_hash,
    "expected_outpoint": {
        "txid": funding_txid,
        "vout": int(funding_vout),
    },
    "outcome": outcome,
    "block_height": block_height,
    "block_hash": block_hash,
    "block_hex": rpc("getblock", block_hash, "0"),
    "transaction_position": transactions.index(terminal_txid),
    "txid": terminal_txid,
    "wtxid": transaction["hash"],
    "minimum_confirmation_depth": int(minimum_depth),
    "continuation_headers": [
        header_at(height) for height in range(checkpoint_height + 1, block_height + 1)
    ],
    "confirmation_headers": [
        header_at(height) for height in range(block_height + 1, tip_height + 1)
    ],
}

with open(output_path, "x", encoding="ascii", newline="\n") as handle:
    json.dump(evidence, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
}

verify_regtest_v2() {
  local evidence_path="$1"
  local settlement_id="$2"
  local terms_hash="$3"
  local outcome="$4"
  local funding_txid="$5"
  local funding_vout="$6"
  local funding_amount="$7"
  local destination_spk="$8"

  local result
  result="$(cargo_f5 verify-regtest-evidence "$evidence_path" "$AUTHORITY_ROOT" \
    "$AUTHORITY_PIN" "$OBSERVER_STATE" "$settlement_id" \
    "$terms_hash" "$outcome" "$funding_txid" \
    "$funding_vout" "$funding_amount" "$FEE_SAT" "$destination_spk")"
  printf '%s\n' "$result"
  grep -qx 'evidence_codec=v2' <<<"$result"
  grep -qx 'header_authority=regtest-genesis-rooted-v2' <<<"$result"
  grep -qx 'external_authority_pin_verified=true' <<<"$result"
  grep -qx 'uspe_state=EvidenceVerification' <<<"$result"
}

bitcoind -regtest -datadir="$REGTEST_DATADIR" -rpcport="$RPCPORT" -listen=0 \
  -fallbackfee=0.0001 -txindex=1 -daemon
for _ in $(seq 1 30); do
  if btc getblockchaininfo >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
btc getblockchaininfo >/dev/null
btc createwallet e2e >/dev/null 2>&1 || btc loadwallet e2e >/dev/null 2>&1 || true

DERIVED="$(cargo_f5 derive)"
ADDRESS="$(sed -n 's/^address=//p' <<<"$DERIVED")"
OUR_SPK="$(sed -n 's/^script_pubkey=//p' <<<"$DERIVED")"
test -n "$ADDRESS"
test -n "$OUR_SPK"

MINER="$(wbtc getnewaddress)"
wbtc generatetoaddress 1 "$MINER" >/dev/null
wbtc generatetoaddress 100 "$ADDRESS" >/dev/null

# Freeze the local canonical chain before either terminal transaction exists.
# Evidence may extend this authority, but cannot replace or self-nominate it.
AUTHORITY_CHECKPOINT_HEIGHT="$(btc getblockcount)"
write_regtest_authority_input "$AUTHORITY_CHECKPOINT_HEIGHT" "$AUTHORITY_INPUT"
mkdir -m 0700 -- "$OBSERVER_STATE"
AUTHORITY_RESULT="$(cargo_f5 create-regtest-authority "$AUTHORITY_ROOT" "$AUTHORITY_INPUT")"
printf '%s\n' "$AUTHORITY_RESULT"
AUTHORITY_PIN="$(sed -n 's/^authority_pin=//p' <<<"$AUTHORITY_RESULT")"
test -n "$AUTHORITY_PIN"
grep -qx 'authority_store_created_once=true' <<<"$AUTHORITY_RESULT"

read_funding() {
  local txid="$1"
  local address="$2"
  local raw
  raw="$(btc getrawtransaction "$txid" true)"
  read -r VOUT AMT_SAT SPK < <(RAW_TRANSACTION="$raw" python3 - "$address" <<'PY'
import json
import os
import sys

address = sys.argv[1]
transaction = json.loads(os.environ["RAW_TRANSACTION"])
for output in transaction["vout"]:
    script = output["scriptPubKey"]
    if script.get("address") == address:
        print(output["n"], round(output["value"] * 100_000_000), script["hex"])
        break
PY
  )
}

destination_script() {
  local address
  address="$(wbtc getnewaddress)"
  wbtc getaddressinfo "$address" | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["scriptPubKey"])'
}

FUND_TXID="$(wbtc sendtoaddress "$ADDRESS" 0.5)"
wbtc generatetoaddress 1 "$ADDRESS" >/dev/null
read_funding "$FUND_TXID" "$ADDRESS"
if [[ "$OUR_SPK" != "$SPK" ]]; then
  echo "FAIL: Rust and Bitcoin Core scriptPubKey differ" >&2
  exit 1
fi
CLAIM_VOUT="$VOUT"
CLAIM_AMOUNT="$AMT_SAT"
CLAIM_DEST="$(destination_script)"
CLAIM_HEX="$(cargo_f5 build-claim "$FUND_TXID" "$CLAIM_VOUT" "$CLAIM_AMOUNT" \
  "$FEE_SAT" "$CLAIM_DEST")"
CLAIM_TXID="$(btc sendrawtransaction "$CLAIM_HEX")"
wbtc generatetoaddress "$MINIMUM_DEPTH" "$ADDRESS" >/dev/null
CLAIM_SETTLEMENT="$(printf '41%.0s' {1..32})"
CLAIM_TERMS="$(printf '42%.0s' {1..32})"
CLAIM_EVIDENCE="$REGTEST_DATADIR/claim-v2.json"
write_regtest_v2_evidence claim "$CLAIM_TXID" "$CLAIM_SETTLEMENT" "$CLAIM_TERMS" \
  "$FUND_TXID" "$CLAIM_VOUT" "$AUTHORITY_CHECKPOINT_HEIGHT" "$CLAIM_EVIDENCE"
verify_regtest_v2 "$CLAIM_EVIDENCE" "$CLAIM_SETTLEMENT" "$CLAIM_TERMS" claim \
  "$FUND_TXID" "$CLAIM_VOUT" "$CLAIM_AMOUNT" "$CLAIM_DEST"

FUND2_TXID="$(wbtc sendtoaddress "$ADDRESS" 0.4)"
wbtc generatetoaddress 1 "$ADDRESS" >/dev/null
read_funding "$FUND2_TXID" "$ADDRESS"
FUND2_VOUT="$VOUT"
FUND2_AMOUNT="$AMT_SAT"
wbtc generatetoaddress "$CSV_BLOCKS" "$ADDRESS" >/dev/null
REFUND_DEST="$(destination_script)"
REFUND_HEX="$(cargo_f5 build-refund "$FUND2_TXID" "$FUND2_VOUT" "$FUND2_AMOUNT" \
  "$FEE_SAT" "$REFUND_DEST")"
REFUND_TXID="$(btc sendrawtransaction "$REFUND_HEX")"
wbtc generatetoaddress "$MINIMUM_DEPTH" "$ADDRESS" >/dev/null
REFUND_SETTLEMENT="$(printf '43%.0s' {1..32})"
REFUND_TERMS="$(printf '44%.0s' {1..32})"
REFUND_EVIDENCE="$REGTEST_DATADIR/refund-v2.json"
write_regtest_v2_evidence refund "$REFUND_TXID" "$REFUND_SETTLEMENT" "$REFUND_TERMS" \
  "$FUND2_TXID" "$FUND2_VOUT" "$AUTHORITY_CHECKPOINT_HEIGHT" "$REFUND_EVIDENCE"
verify_regtest_v2 "$REFUND_EVIDENCE" "$REFUND_SETTLEMENT" "$REFUND_TERMS" refund \
  "$FUND2_TXID" "$FUND2_VOUT" "$FUND2_AMOUNT" "$REFUND_DEST"

echo "F5 Regtest V2 E2E PASS: claim/refund crossed the independently pinned authority"
