#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
FORGE_BIN="${FORGE_BIN:-forge}"

install_exact() {
  local destination="$1"
  local dependency="$2"
  if [ -e "$CONTRACT_ROOT/lib/$destination" ]; then
    printf 'keeping existing %s; the release gate will verify its compiled-source digest\n' "$destination"
    return
  fi
  "$FORGE_BIN" install --root "$CONTRACT_ROOT" --no-git --shallow "$destination=$dependency"
}

install_exact forge-std \
  'foundry-rs/forge-std@rev=3b20d60d14b343ee4f908cb8079495c07f5e8981'
install_exact openzeppelin-contracts \
  'OpenZeppelin/openzeppelin-contracts@rev=69c8def5f222ff96f2b5beff05dfba996368aa79'

printf '%s\n' 'dependencies installed; run ./scripts/check_release.sh'
