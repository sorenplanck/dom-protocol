#!/usr/bin/env bash
set -Eeuo pipefail

repo="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "erro: execute dentro de um repositório Git" >&2
  exit 2
}
repo_real="$(realpath "$repo")"
case "$repo_real" in
  /home/leonardov/dom-release|/home/leonardov/dom-protocol|/home/leonardov/dom-wallet-v3)
    echo "RECUSADO: fonte oficial somente leitura: $repo_real" >&2
    exit 3
    ;;
esac
if [[ "$repo_real" != "/home/leonardov/dom-scriptless-dev/dom-scriptless-contracts" ]]; then
  echo "erro: clone DOM Scriptless Contracts inesperado: $repo_real" >&2
  exit 4
fi

# Fail closed if an instrument this preflight depends on is absent. Without this,
# a missing tool makes its command fail, and a failing command in an `if` or under
# `!` reads as "nothing found" — so the isolation checks below would PASS exactly
# when they became unable to measure anything. Exit 6 = missing tooling.
require_tools() {
  local t missing=()
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  if (( ${#missing[@]} > 0 )); then
    echo "erro: ferramentas obrigatórias ausentes: ${missing[*]}" >&2
    echo "erro: o preflight falha fechado; instale-as antes de reexecutar." >&2
    exit 6
  fi
}
require_tools grep git realpath tee date cargo

log_dir="$(realpath "$repo/../logs")"
log="$log_dir/preflight.log"
exec > >(tee -a "$log") 2>&1

echo "== preflight $(date --iso-8601=seconds) =="
echo "+ git rev-parse HEAD"
git rev-parse HEAD
echo "+ git branch --show-current"
git branch --show-current

base=769822562565f18ef55423dc992e7aa661206b4a
tag=baseline/scriptless-2026-08-04
[[ "$(git rev-parse "${tag}^{commit}")" == "$base" ]]
git merge-base --is-ancestor "$base" HEAD
[[ "$(git config --get core.hooksPath)" == ".githooks" ]]
[[ -x .githooks/pre-push ]]
# No 'origin' remote may exist. Status is inspected explicitly: 0 = found (refuse),
# 1 = absent (correct), anything else = the search itself failed and must not be
# mistaken for absence.
origin_rc=0
git remote | grep -qxF -- origin || origin_rc=$?
case "$origin_rc" in
  0)
    echo "erro: remote 'origin' presente; o isolamento exige sua ausência" >&2
    exit 6
    ;;
  1) : ;;
  *)
    echo "erro: falha ao inspecionar os remotes (status $origin_rc)" >&2
    exit 7
    ;;
esac

while IFS= read -r remote; do
  [[ "$(git remote get-url --push "$remote")" == "no_push://push-disabled" ]]
done < <(git remote)

# Forbidden constructions in dom-adaptor. Status is inspected explicitly:
# 0 = found (refuse), 1 = clean, anything else = the search itself failed and must
# not be mistaken for a clean tree.
forbidden_rc=0
forbidden_hits="$(grep -rnE -- 'unsafe[[:space:]]*\{|todo!\(|unimplemented!\(' crates/dom-adaptor)" || forbidden_rc=$?
case "$forbidden_rc" in
  0)
    printf '%s\n' "$forbidden_hits"
    echo "erro: construção proibida em dom-adaptor" >&2
    exit 5
    ;;
  1) : ;;
  *)
    echo "erro: falha ao varrer crates/dom-adaptor (status $forbidden_rc)" >&2
    exit 7
    ;;
esac

echo "+ cargo metadata --no-deps --format-version 1"
cargo metadata --no-deps --format-version 1 >/dev/null
echo "PREFLIGHT OK"
