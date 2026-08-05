#!/usr/bin/env bash
set -Eeuo pipefail

repo="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "error: run this script inside a Git repository" >&2
  exit 2
}
repo_real="$(realpath "$repo")"
case "$repo_real" in
  /home/leonardov/dom-release|/home/leonardov/dom-protocol|/home/leonardov/dom-wallet-v3)
    echo "RECUSADO: fonte oficial somente leitura: $repo_real" >&2
    exit 3
    ;;
esac
common_git_dir="$(realpath "$(git rev-parse --git-common-dir)")"
expected_common_git_dir=/home/leonardov/dom-scriptless-dev/dom-scriptless-contracts/.git
if [[ "$common_git_dir" != "$expected_common_git_dir" ]]; then
  echo "error: unexpected DOM Scriptless Contracts clone or worktree: $repo_real" >&2
  exit 4
fi

log_dir=/home/leonardov/dom-scriptless-dev/logs
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
  echo "error: prohibited construction in dom-adaptor" >&2
  exit 5
fi

echo "+ cargo metadata --no-deps --format-version 1"
cargo metadata --no-deps --format-version 1 >/dev/null
echo "PREFLIGHT OK"
