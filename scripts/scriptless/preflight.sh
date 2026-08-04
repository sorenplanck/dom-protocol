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
! git remote | rg -x origin

while IFS= read -r remote; do
  [[ "$(git remote get-url --push "$remote")" == "no_push://push-disabled" ]]
done < <(git remote)

if rg -n 'unsafe[[:space:]]*\{|todo!\(|unimplemented!\(' crates/dom-adaptor; then
  echo "erro: construção proibida em dom-adaptor" >&2
  exit 5
fi

echo "+ cargo metadata --no-deps --format-version 1"
cargo metadata --no-deps --format-version 1 >/dev/null
echo "PREFLIGHT OK"
