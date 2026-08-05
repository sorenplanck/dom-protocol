#!/usr/bin/env bash
set -Eeuo pipefail

repo="$(git rev-parse --show-toplevel 2>/dev/null)" || exit 2
repo_real="$(realpath "$repo")"
case "$repo_real" in
  /home/leonardov/dom-release|/home/leonardov/dom-protocol|/home/leonardov/dom-wallet-v3)
    echo "REFUSED: read-only official source: $repo_real" >&2
    exit 3
    ;;
esac
common_git_dir="$(realpath "$(git rev-parse --git-common-dir)")"
[[ "$common_git_dir" == "/home/leonardov/dom-scriptless-dev/dom-scriptless-contracts/.git" ]]
cd "$repo"

log=/home/leonardov/dom-scriptless-dev/logs/phase1-gate.log
exec > >(tee -a "$log") 2>&1
echo "== phase1-gate $(date --iso-8601=seconds) =="

sha256sum --check test-vectors/scriptless/MANIFEST.sha256
[[ "$(rg -c '^VECTOR_BEGIN id=V[0-9]{2} ' test-vectors/scriptless/scad0/DOM_SCAD0_8_VETORES_2026-08-03.txt)" -eq 8 ]]

gate_g1a=docs/scriptless/phase-1a/GATE-G1A.md
gate_g1b=docs/scriptless/phase-1b/GATE-G1B.md
[[ -f "$gate_g1a" && -f "$gate_g1b" ]]

pending_g1a="$(rg -c '^- \[ \]' "$gate_g1a" || true)"
pending_g1b="$(rg -c '^- \[ \]' "$gate_g1b" || true)"
pending_g1a="${pending_g1a:-0}"
pending_g1b="${pending_g1b:-0}"

echo "G1a pending items: $pending_g1a"
echo "G1b pending items: $pending_g1b"

if [[ "$pending_g1a" -gt 0 || "$pending_g1b" -gt 0 ]]; then
  [[ "$pending_g1a" -eq 0 ]] || echo "G1a NOT APPROVED" >&2
  [[ "$pending_g1b" -eq 0 ]] || echo "G1b NOT APPROVED" >&2
  echo "PHASE 1 NOT APPROVED: production requires both G1a and G1b with no pending items and separate formal approval." >&2
  exit 1
fi

echo "G1a and G1b checklists contain no open items; separate evidence and formal approvals are still required."
