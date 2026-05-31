#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-packaging/windows/portable}"

required_files=(
  "${ROOT}/README.md"
  "${ROOT}/layout.txt"
  "${ROOT}/build_portable.ps1"
  "${ROOT}/update_portable.ps1"
)

for file in "${required_files[@]}"; do
  if [[ ! -f "${file}" ]]; then
    echo "missing required file: ${file}" >&2
    exit 1
  fi
done

required_terms=(
  "bin/"
  "config/"
  "data/"
  "wallets"
  "chain"
  "logs"
  "backups"
  "cache"
  "VERSION.txt"
)

for term in "${required_terms[@]}"; do
  if ! grep -R -F -- "${term}" "${ROOT}/README.md" "${ROOT}/layout.txt" >/dev/null; then
    echo "portable docs missing required layout term: ${term}" >&2
    exit 1
  fi
done

if ! grep -F "data\\wallets" "${ROOT}/update_portable.ps1" >/dev/null; then
  echo "update script must reference data\\wallets backup path" >&2
  exit 1
fi

if ! grep -F "backups\\wallets-" "${ROOT}/update_portable.ps1" >/dev/null; then
  echo "update script must create timestamped wallet backups" >&2
  exit 1
fi

if grep -R -E "(password|seed phrase|private key|bearer token|api token)[[:space:]]*[:=][[:space:]]*[^<[:space:]#]" "${ROOT}" >/dev/null; then
  echo "portable package contains what looks like a secret assignment" >&2
  exit 1
fi

echo "windows portable package layout validation PASS"
