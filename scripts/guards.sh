#!/usr/bin/env bash
# Rust-independent interoperability policy gate.
set -Eeuo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo="$(CDPATH='' cd -- "$script_dir/.." && pwd -P)"

if [[ ! -f "$repo/Cargo.toml" || ! -f "$script_dir/guard_layer_policy.py" ]]; then
  printf '%s\n' 'LAYER_GUARDS = FAIL (workspace or policy scanner is absent)' >&2
  exit 1
fi

export PYTHONDONTWRITEBYTECODE=1
exec python3 -B "$script_dir/guard_layer_policy.py" --root "$repo" "$@"
