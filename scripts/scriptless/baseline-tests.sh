#!/usr/bin/env bash
set -Eeuo pipefail

repo="$(git rev-parse --show-toplevel 2>/dev/null)" || exit 2
repo_real="$(realpath "$repo")"
case "$repo_real" in
  /home/leonardov/dom-release|/home/leonardov/dom-protocol|/home/leonardov/dom-wallet-v3)
    echo "RECUSADO: fonte oficial somente leitura: $repo_real" >&2
    exit 3
    ;;
esac
[[ "$repo_real" == "/home/leonardov/dom-scriptless-dev/dom-scriptless-contracts" ]]
cd "$repo"

log="$(realpath "$repo/../logs")/baseline-tests.log"
exec > >(tee -a "$log") 2>&1
export CARGO_BUILD_JOBS=4

run() {
  echo "+ $*"
  "$@"
}

echo "== baseline-tests $(date --iso-8601=seconds) =="
run cargo metadata --no-deps --format-version 1
run cargo fmt --all --check
run cargo check --workspace --jobs 4
run cargo test -p dom-adaptor --jobs 4
echo "BASELINE MINIMUM OK"
