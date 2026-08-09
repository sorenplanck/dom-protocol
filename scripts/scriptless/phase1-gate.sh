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
# Identify the REPOSITORY, not the checkout path, so linked worktrees of
# dom-scriptless-contracts are accepted. --git-common-dir resolves to the
# shared .git of the main checkout from every worktree of that repository.
git_common_real="$(realpath "$(git rev-parse --git-common-dir)")"
[[ "$git_common_real" == /home/leonardov/dom-scriptless-dev/dom-scriptless-contracts/* ]]
cd "$repo"

# Fail closed if an instrument this gate depends on is absent. Without this,
# a missing tool makes its command fail, a failing command in an `if` or behind
# `|| true` reads as "nothing found", and the gate would approve everything
# precisely because it could not measure anything. Exit 6 = missing tooling.
require_tools() {
  local t missing=()
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  if (( ${#missing[@]} > 0 )); then
    echo "ERRO: ferramentas obrigatórias ausentes: ${missing[*]}" >&2
    echo "ERRO: o gate falha fechado; instale-as antes de reexecutar." >&2
    exit 6
  fi
}
require_tools grep sha256sum git realpath tee date

# Emit the number of matching lines. `grep -c` exits 1 on zero matches, which is
# a legitimate result, so only status 0 and 1 are accepted; anything else (missing
# file, unreadable file, broken regex) and any non-numeric output is an error and
# is propagated to the caller rather than silently becoming 0.
count_matches() {
  local pattern="$1" file="$2" out rc
  out="$(grep -cE -- "$pattern" "$file")" && rc=0 || rc=$?
  (( rc <= 1 )) || return "$rc"
  [[ "$out" =~ ^[0-9]+$ ]] || return 90
  printf '%s\n' "$out"
}

log="$(realpath "$repo/../logs")/phase1-gate.log"
exec > >(tee -a "$log") 2>&1
echo "== phase1-gate $(date --iso-8601=seconds) =="

vectors=test-vectors/scriptless/scad0/DOM_SCAD0_8_VETORES_2026-08-03.txt

sha256sum --check test-vectors/scriptless/MANIFEST.sha256
if ! vector_count="$(count_matches '^VECTOR_BEGIN id=V[0-9]{2} ' "$vectors")"; then
  echo "ERRO: não foi possível contar os vetores em $vectors" >&2
  exit 7
fi
[[ "$vector_count" -eq 8 ]]

gate_g1a=docs/scriptless/phase-1a/GATE-G1A.md
gate_g1b=docs/scriptless/phase-1b/GATE-G1B.md
[[ -f "$gate_g1a" && -f "$gate_g1b" ]]

if ! pending_g1a="$(count_matches '^- \[ \]' "$gate_g1a")"; then
  echo "ERRO: não foi possível contar as pendências em $gate_g1a" >&2
  exit 7
fi
if ! pending_g1b="$(count_matches '^- \[ \]' "$gate_g1b")"; then
  echo "ERRO: não foi possível contar as pendências em $gate_g1b" >&2
  exit 7
fi

echo "Pendências G1a: $pending_g1a"
echo "Pendências G1b: $pending_g1b"

if [[ "$pending_g1a" -gt 0 || "$pending_g1b" -gt 0 ]]; then
  [[ "$pending_g1a" -eq 0 ]] || echo "G1a NÃO APROVADO" >&2
  [[ "$pending_g1b" -eq 0 ]] || echo "G1b NÃO APROVADO" >&2
  echo "FASE 1 NÃO APROVADA: produção exige G1a E G1b sem pendências e formalmente aprovados." >&2
  exit 1
fi

echo "Checklists G1a e G1b sem pendências abertas; confirmar evidências e aprovações formais separadas."
