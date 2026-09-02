#!/usr/bin/env bash
# Sepolia — shared environment contract for every Sepolia runner.
#
# RECONSTRUCTION (2026-09-02): this artifact never existed in this repository;
# rebuilt from the roadmap requirement over the real harness env contracts
# (F3_ANVIL_* consumed by f3-harness, F4_SEPOLIA_* by f4-harness).
#
# Source this file; it validates fail-closed and exports the common facts:
#   required from the operator (never defaulted, never echoed):
#     SEPOLIA_RPC_URL        https endpoint
#     SEPOLIA_PRIVATE_KEY    funded test key (0x…)
#   derived and verified here:
#     SEPOLIA_CHAIN_ID=11155111 (refused if the endpoint disagrees)
#     SEPOLIA_ACCOUNT        address of the key, via cast
set -euo pipefail

SEPOLIA_CHAIN_ID=11155111
: "${SEPOLIA_RPC_URL:?SEPOLIA_RPC_URL is required}"
: "${SEPOLIA_PRIVATE_KEY:?SEPOLIA_PRIVATE_KEY is required}"
case "$SEPOLIA_RPC_URL" in
  https://*) ;;
  *) echo "SEPOLIA_RPC_URL must be https" >&2; exit 1 ;;
esac

CAST="${CAST:-cast}"
command -v "$CAST" >/dev/null || { echo "cast not found (install foundry)" >&2; exit 1; }

got_chain="$("$CAST" chain-id --rpc-url "$SEPOLIA_RPC_URL")"
if [ "$got_chain" != "$SEPOLIA_CHAIN_ID" ]; then
  echo "endpoint chain-id $got_chain is not Sepolia ($SEPOLIA_CHAIN_ID): refusing" >&2
  exit 1
fi

SEPOLIA_ACCOUNT="$("$CAST" wallet address --private-key "$SEPOLIA_PRIVATE_KEY")"
balance_wei="$("$CAST" balance "$SEPOLIA_ACCOUNT" --rpc-url "$SEPOLIA_RPC_URL")"
if [ "$balance_wei" = "0" ]; then
  echo "account $SEPOLIA_ACCOUNT has zero balance on Sepolia: refusing" >&2
  exit 1
fi

export SEPOLIA_CHAIN_ID SEPOLIA_RPC_URL SEPOLIA_PRIVATE_KEY SEPOLIA_ACCOUNT CAST
echo "sepolia env ok: account $SEPOLIA_ACCOUNT (balance ${balance_wei} wei)"
