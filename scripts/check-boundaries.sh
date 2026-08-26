#!/usr/bin/env bash
# Architecture boundaries for the merged DOM repository.
#
# Transported from `dom-contracts/scripts/check-boundaries.sh`. It was the one
# guard that did NOT travel with the interoperability layer, and it is the one
# that adjudicates machine-local paths — a question that was being decided by
# hand until it was found missing.
#
# Three of its checks travel verbatim. Two were restructured, and each says why
# below. Nothing was relaxed: both restructurings are strictly stronger than
# what they replace, or freeze a debt that was previously invisible.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

status=0

# ─────────────────────────────────────────────────────────────────────────────
# 1. Machine-local paths — RESTRUCTURED into an enumerated exception list.
#
# The original failed on any hit across the whole repository. That cannot pass
# here: the mainnet node itself carries four such files on `release/mainnetv2`,
# and the node is immutable in this branch. Failing repository-wide would make
# the guard permanently red, which teaches people to ignore it.
#
# So the node's existing debt is enumerated, by file AND by line count. The
# guard fails if a NEW file appears, or if a listed file's count CHANGES in
# either direction. That is not a relaxation: before, the debt was invisible
# and unbounded; now it is named, frozen, and cannot grow by one line without
# turning this red. Anything the layer brought must be clean — this list holds
# node debt only.
declare -A NODE_LOCAL_PATH_DEBT=(
  ["docs/RELEASE_V3_RUNBOOK.md"]=5
  ["docs/HARD_FORK_V3_IMPLEMENTATION_REPORT.md"]=2
  ["wallet-desktop/src-tauri/src/wallet_manager.rs"]=1
  ["reports/WALLET_V3_NODE_RPC_CAPABILITIES.md"]=1
)

local_path_hits="$(
  git grep -c -I -E '(/home/|/Users/|[A-Za-z]:\\Users\\)' -- \
    . ':(exclude)scripts/check-boundaries.sh' || true
)"

while IFS=: read -r file count; do
  [[ -z "$file" ]] && continue
  expected="${NODE_LOCAL_PATH_DEBT[$file]:-}"
  if [[ -z "$expected" ]]; then
    echo "FAIL machine-local path in tracked content: $file ($count line(s))" >&2
    echo "     Not in the frozen node-debt list. Content brought into this" >&2
    echo "     repository must carry no machine-local path." >&2
    status=1
  elif [[ "$count" != "$expected" ]]; then
    echo "FAIL machine-local path count changed: $file has $count, frozen at $expected" >&2
    status=1
  fi
done <<<"$local_path_hits"

for file in "${!NODE_LOCAL_PATH_DEBT[@]}"; do
  if ! grep -q "^${file}:" <<<"$local_path_hits"; then
    echo "FAIL $file no longer carries machine-local paths (frozen at ${NODE_LOCAL_PATH_DEBT[$file]})" >&2
    echo "     The debt shrank — remove its entry from the frozen list." >&2
    status=1
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
# 2. Verbatim checks. Each still means exactly what it meant.
if git grep -n -I -E \
    '(dom-wallet-v3|dom_wallet_v3|dom-wallet-scriptless-vault)' -- \
    Cargo.toml Cargo.lock 'crates/**/Cargo.toml' >&2; then
    echo "FAIL ordinary DOM Wallet dependency found" >&2
    status=1
fi

if git grep -n -I -E 'path[[:space:]]*=[[:space:]]*"/' -- \
    Cargo.toml Cargo.lock 'crates/**/Cargo.toml' >&2; then
    echo "FAIL absolute Cargo path dependency found" >&2
    status=1
fi

if git grep -n -I -E '^\[patch\.' -- Cargo.toml 'crates/**/Cargo.toml' >&2; then
    echo "FAIL tracked Cargo patch override found" >&2
    status=1
fi

if git grep -n -I -E \
    '(mainnet-contracts|enable-mainnet-contracts|mainnet_funding)' -- \
    Cargo.toml 'crates/**/*.rs' 'crates/**/Cargo.toml' >&2; then
    echo "FAIL mainnet contract funding surface found" >&2
    status=1
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. The pinned-revision block — RESTRUCTURED, its premise dissolved by the
#    merge (the same shape as D-ORQ-19).
#
# The original required dom-{adaptor,consensus,core,crypto,serialization} to be
# declared as git dependencies on sorenplanck/dom-protocol at one 40-hex rev,
# and required Cargo.lock to resolve that exact rev. In this repository those
# crates ARE the workspace — there is no git dependency to pin, so the original
# would find an empty set and fail on its own emptiness.
#
# What it was protecting is "no DOM crate carries a divergent revision". The
# equivalent property here is stronger and cannot rot, because it names no
# constant: NO `dom-*` crate may be a git dependency at all. Every one must be
# a workspace member, which makes a divergent revision unrepresentable rather
# than merely detected.
dom_git_dependencies="$(
    git grep -h -I -E '^dom-[a-z0-9-]+[[:space:]]*=[[:space:]]*\{[^}]*git[[:space:]]*=' -- \
        Cargo.toml 'crates/**/Cargo.toml' || true
)"
if [[ -n "$dom_git_dependencies" ]]; then
    echo "FAIL a dom-* crate is declared as a git dependency:" >&2
    printf '     %s\n' "$dom_git_dependencies" >&2
    echo "     In the merged repository every dom-* crate must be a workspace" >&2
    echo "     member. A git dependency can carry a divergent revision; a" >&2
    echo "     member cannot." >&2
    status=1
fi

if [[ $status -ne 0 ]]; then
    echo "BOUNDARIES = FAIL" >&2
    exit 1
fi

echo "BOUNDARIES = PASS"
