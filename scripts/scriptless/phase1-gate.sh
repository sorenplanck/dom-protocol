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

log="$(realpath "$repo/../logs")/phase1-gate.log"
exec > >(tee -a "$log") 2>&1
echo "== phase1-gate $(date --iso-8601=seconds) =="

sha256sum --check test-vectors/scriptless/MANIFEST.sha256
[[ "$(rg -c '^VECTOR_BEGIN id=V[0-9]{2} ' test-vectors/scriptless/scad0/DOM_SCAD0_8_VETORES_2026-08-03.txt)" -eq 8 ]]
pending="$(rg -c '^- \[ \]' docs/scriptless/phase-1/GATE-G1.md)"
echo "Itens pendentes no Gate G1: $pending"

if [[ "$pending" -gt 0 ]]; then
  echo "GATE G1 NÃO APROVADO: requisitos G1a/G1b permanecem pendentes." >&2
  exit 1
fi

echo "erro: o bootstrap não está autorizado a declarar G1 aprovado" >&2
exit 2
