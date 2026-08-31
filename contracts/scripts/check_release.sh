#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
FORGE_BIN="${FORGE_BIN:-forge}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

BUILD_A="$(mktemp -d "${TMPDIR:-/tmp}/dom-evm-release-a.XXXXXX")"
BUILD_B="$(mktemp -d "${TMPDIR:-/tmp}/dom-evm-release-b.XXXXXX")"
cleanup() {
  case "$BUILD_A:$BUILD_B" in
    /tmp/dom-evm-release-a.*:/tmp/dom-evm-release-b.* | \
      "${TMPDIR:-/tmp}"/dom-evm-release-a.*:"${TMPDIR:-/tmp}"/dom-evm-release-b.*)
      rm -rf -- "$BUILD_A" "$BUILD_B"
      ;;
    *)
      printf '%s\n' 'refusing to remove unexpected temporary paths' >&2
      ;;
  esac
}
trap cleanup EXIT INT TERM

cd "$CONTRACT_ROOT"

"$FORGE_BIN" fmt --check

build_once() {
  local destination="$1"
  "$FORGE_BIN" build \
    src/ConditionLockV2.sol \
    src/ConditionLockERC20V2.sol \
    script/Deploy.s.sol \
    --offline \
    --no-cache \
    --out "$destination/out" \
    --cache-path "$destination/cache" \
    --build-info \
    --build-info-path "$destination/build-info" \
    -D warnings
}

build_once "$BUILD_A"
build_once "$BUILD_B"

for artifact in \
  ConditionLockV2.sol/ConditionLockV2.json \
  ConditionLockERC20V2.sol/ConditionLockERC20V2.json \
  Deploy.s.sol/DeployScript.json
do
  cmp "$BUILD_A/out/$artifact" "$BUILD_B/out/$artifact"
done

"$PYTHON_BIN" scripts/release_manifest.py inspect-dependencies --artifacts-dir "$BUILD_A/out" >/dev/null
"$FORGE_BIN" test --offline --summary
"$PYTHON_BIN" -m unittest discover -s scripts/tests -p 'test_*.py' -v

printf '%s\n' 'DOM EVM contract release gate passed'
