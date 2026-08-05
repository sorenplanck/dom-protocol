#!/usr/bin/env bash
set -Eeuo pipefail

repo="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "error: run this script inside a Git repository" >&2
  exit 2
}
repo_real="$(realpath "$repo")"
case "$repo_real" in
  /home/leonardov/dom-release|/home/leonardov/dom-protocol|/home/leonardov/dom-wallet-v3)
    echo "REFUSED: read-only official source: $repo_real" >&2
    exit 3
    ;;
esac
common_git_dir="$(realpath "$(git rev-parse --git-common-dir)")"
[[ "$common_git_dir" == "/home/leonardov/dom-scriptless-dev/dom-scriptless-contracts/.git" ]]

log=/home/leonardov/dom-scriptless-dev/logs/verify-isolation.log
exec > >(tee -a "$log") 2>&1
echo "== verify-isolation $(date --iso-8601=seconds) =="

dom_source=/home/leonardov/dom-release
wallet_source=/home/leonardov/dom-wallet-v3
dom_base=769822562565f18ef55423dc992e7aa661206b4a
wallet_previous_base=abb573168be75b23269343559e4e94e28e9d33e7
wallet_base=1868e61bc39eca223d794348d70e48668ad06708
wallet_tree=5c572e4b5d083dbb7caa0ca608c0d2864add9f6c

[[ "$(git -C "$dom_source" rev-parse HEAD)" == "$dom_base" ]]
[[ "$(git -C "$dom_source" branch --show-current)" == "release/mainnet" ]]
[[ "$(git -C "$wallet_source" rev-parse HEAD)" == "$wallet_base" ]]
[[ "$(git -C "$wallet_source" rev-parse 'HEAD^{tree}')" == "$wallet_tree" ]]
[[ "$(git -C "$wallet_source" branch --show-current)" == "redesign/restore-remote-scan" ]]
rg -qx 'version = "0.3.2"' "$wallet_source/Cargo.toml"

dom_status="$(git -C "$dom_source" status --porcelain=v1 --untracked-files=all)"
wallet_status="$(git -C "$wallet_source" status --porcelain=v1 --untracked-files=all)"
[[ "$(printf '%s\n' "$dom_status" | sha256sum | cut -d' ' -f1)" == "b7fe0995273a0c767016a346914f2ccd2673bc1f32275f3ac42391175689e34f" ]]
[[ "$(printf '%s\n' "$wallet_status" | sha256sum | cut -d' ' -f1)" == "af9a886a38c5141b0020b155424a8b83fdf2f734d353c8a07841a16b8ce93a3d" ]]

sha256sum -c <(printf '%s  %s\n' \
  e036be3b8ae8f081a214958ed47e0d311c14e91277cbc57797f7276ef8c66064 "$dom_source/crates/dom-node/src/bin/adaptor_parity_probe.rs" \
  88efe0f79ee4a795d3918e8c431b1477e1d5909a96445a8048309de01195e7f1 "$wallet_source/reports/DOM_NODE_IBD_SYNC_INVESTIGATION_2026-07-29.md" \
  41741803d8f95c64ca40d8ffc6584f07cb833736f9c88264debd1f9e30d76d68 "$wallet_source/reports/MISSAO_1_B1_INPUTS_CONGELADOS_2026-08-04.md" \
  71936f8fca1bacb5901a7add3c791bb8832b0afb5d81fa487119de2a0cd84059 "$wallet_source/reports/MISSAO_2_HEIGHT_LOCKED_RPC_2026-08-04.md")

[[ ! -e "$repo/crates/dom-node/src/bin/adaptor_parity_probe.rs" ]]
wallet_clone=/home/leonardov/dom-scriptless-dev/dom-wallet-v3-scriptless
[[ ! -e "$wallet_clone/reports/DOM_NODE_IBD_SYNC_INVESTIGATION_2026-07-29.md" ]]
[[ ! -e "$wallet_clone/reports/MISSAO_1_B1_INPUTS_CONGELADOS_2026-08-04.md" ]]
[[ ! -e "$wallet_clone/reports/MISSAO_2_HEIGHT_LOCKED_RPC_2026-08-04.md" ]]

[[ "$(git rev-parse 'baseline/scriptless-2026-08-04^{commit}')" == "$dom_base" ]]
[[ "$(git -C "$wallet_clone" rev-parse 'baseline/scriptless-wallet-2026-08-04^{commit}')" == "$wallet_previous_base" ]]
[[ "$(git -C "$wallet_clone" rev-parse 'baseline/scriptless-wallet-v0.3.2-2026-08-04^{commit}')" == "$wallet_base" ]]
[[ "$(git -C "$wallet_clone" rev-parse HEAD)" == "$wallet_base" ]]
[[ "$(git -C "$wallet_clone" rev-parse 'HEAD^{tree}')" == "$wallet_tree" ]]
[[ "$(git -C "$wallet_clone" branch --show-current)" == "feat/scriptless-integration" ]]
git -C "$wallet_clone" diff --quiet
git -C "$wallet_clone" diff --cached --quiet
[[ "$(git config --get core.hooksPath)" == ".githooks" ]]
[[ "$(git -C "$wallet_clone" config --get core.hooksPath)" == ".githooks" ]]
[[ -x "$repo/.githooks/pre-push" && -x "$wallet_clone/.githooks/pre-push" ]]
printf '%s  %s\n' \
  07e168fa9713045f3dd5180393663607023671f884da3535a0188d1aa517c29b \
  "$wallet_clone/.githooks/pre-push" | sha256sum --check
! git remote | rg -x origin
! git -C "$wallet_clone" remote | rg -x origin

for checked_repo in "$repo" "$wallet_clone"; do
  while IFS= read -r remote; do
    [[ "$(git -C "$checked_repo" remote get-url --push "$remote")" == "no_push://push-disabled" ]]
  done < <(git -C "$checked_repo" remote)
  checked_common_git_dir="$(git -C "$checked_repo" rev-parse --git-common-dir)"
  if [[ "$checked_common_git_dir" != /* ]]; then
    checked_common_git_dir="$checked_repo/$checked_common_git_dir"
  fi
  checked_common_git_dir="$(realpath "$checked_common_git_dir")"
  if find "$checked_common_git_dir/objects" -type f -links +1 -print -quit | rg .; then
    echo "error: hardlinked Git object found in $checked_repo" >&2
    exit 6
  fi
done

echo "ISOLATION OK"
