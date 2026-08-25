#!/usr/bin/env bash
# Verify the NAR-DC-P1-007 adjudication against its ratified bytes.
#
# This guard validates normative data only. It implements no state machine,
# funding gate, roster validator, or other protocol behaviour.
#
# It fails closed: a check it cannot perform is a failure, never a skip.
set -Eeuo pipefail

# Anchored to the workspace root, not to the git top level: in the monorepo
# these are different directories, and every path literal below is relative to
# the workspace the guarded crates belong to.
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

record="docs/specifications/normative/NAR-DC-P1-007-phase-state-participant-and-funding-authority-closure.en.md"

failures=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1" >&2; failures=$((failures + 1)); }

echo "== NAR-DC-P1-007 adjudication guard =="

if [[ ! -f "$record" ]]; then
  echo "  FAIL  ratified record is absent: $record" >&2
  echo "ADJUDICATION_GUARD = FAIL (1 violation(s))" >&2
  exit 1
fi

# The canonical table is the numbered enumeration in section 3.2, bounded by the
# section 3.3 heading. Reading it positionally keeps the guard bound to the
# adjudicated list rather than to any prose that merely mentions an edge.
mapfile -t actual < <(
  awk '/^### 3\.2 Decision$/{inside=1; next} /^### 3\.3 /{inside=0} inside' "$record" |
    grep -E '^[[:space:]]*[0-9]{1,2}[[:space:]]+[A-Za-z][A-Za-z0-9]*[[:space:]]+->[[:space:]]+[A-Za-z][A-Za-z0-9]*[[:space:]]*$' |
    sed -E 's/^[[:space:]]*[0-9]{1,2}[[:space:]]+//; s/[[:space:]]+->[[:space:]]+/ -> /; s/[[:space:]]+$//'
)

read -r -d '' expected <<'EOF' || true
Created -> TermsCommitted
TermsCommitted -> SharesCommitted
SharesCommitted -> SharesRevealed
SharesRevealed -> BpCommonCommitted
BpCommonCommitted -> BpCommonEstablished
BpCommonEstablished -> BpNonceCommitted
BpNonceCommitted -> BpRound1Complete
BpRound1Complete -> BpRound2Complete
BpRound2Complete -> OutputFinalized
OutputFinalized -> TemplatesCommitted
TemplatesCommitted -> RefundSigning
RefundSigning -> RefundSigned
RefundSigned -> ClaimSigning
ClaimSigning -> ClaimPrepared
ClaimPrepared -> FundingAuthorized
FundingAuthorized -> FundingBroadcast
FundingBroadcast -> FundingConfirmed
FundingConfirmed -> ClaimBroadcast
FundingConfirmed -> RefundEligible
ClaimBroadcast -> Settled
RefundEligible -> RefundBroadcast
RefundBroadcast -> Refunded
EOF

if [[ ${#actual[@]} -eq 22 ]]; then
  pass "canonical table declares 22 directed edges"
else
  fail "expected 22 directed edges, parsed ${#actual[@]}"
fi

duplicates="$(printf '%s\n' "${actual[@]}" | sort | uniq -d)"
if [[ -z "$duplicates" ]]; then
  pass "every declared edge is unique"
else
  fail "duplicate edge(s) declared: $(printf '%s; ' $duplicates)"
fi

# Ordered comparison. NAR-DC-P1-007 §5 requires "no additional, missing, or
# reordered destination for any origin", and a sorted comparison would accept a
# reordering as an equivalent set.
if diff <(printf '%s\n' "${actual[@]}") <(printf '%s\n' "$expected") >/dev/null; then
  pass "canonical table equals the adjudicated edge list exactly, in order"
else
  fail "canonical table diverges from the adjudicated edge list"
  diff <(printf '%s\n' "${actual[@]}") <(printf '%s\n' "$expected") >&2 || true
fi

# The two shortcuts the adjudication removed must not reappear in the canonical
# table. Section 3.3 names them as removed, so the search is scoped to the table.
shortcut_found=0
for shortcut in "TemplatesCommitted -> RefundSigned" "RefundSigned -> ClaimPrepared"; do
  if grep -Fxq "$shortcut" <<<"$(printf '%s\n' "${actual[@]}")"; then
    fail "removed shortcut present in the canonical table: $shortcut"
    shortcut_found=1
  fi
done
[[ $shortcut_found -eq 0 ]] && pass "neither removed shortcut appears in the canonical table"

# Each phase the published section 9.2 table could not enter must now be entered.
for phase in RefundSigning ClaimSigning RefundBroadcast Refunded; do
  if grep -Eq " -> ${phase}$" <<<"$(printf '%s\n' "${actual[@]}")"; then
    pass "$phase is reachable"
  else
    fail "$phase has no entry edge"
  fi
done

# The four status assertions belong to the section 8 status block. Scoping the
# search to that block, and requiring exactly one occurrence, means prose
# elsewhere in the record cannot satisfy a check, and a line restated twice is
# a divergence rather than a stronger claim.
status_block="$(awk '/^## 8\. Ratification and status$/{inside=1; next} /^## /{inside=0} inside' "$record")"

if [[ -z "$status_block" ]]; then
  fail "section 8 status block is absent"
else
  pass "section 8 status block is present"
  check_status_line() {
    local line="$1" description="$2" occurrences
    occurrences="$(printf '%s\n' "$status_block" | grep -Fxc "$line" || true)"
    if [[ "$occurrences" == "1" ]]; then
      pass "$description"
    else
      fail "$description (expected 1 occurrence in section 8, found ${occurrences:-0})"
    fi
  }
  check_status_line 'PARTICIPANT_CARDINALITY = EXACTLY_TWO_DISTINCT' \
    "participant cardinality is declared exactly two distinct"
  check_status_line 'N_OF_N = OUTSIDE_V1' \
    "n-of-n is declared outside V1"
  check_status_line 'CANONICAL_TRANSITION_EDGES = 22' \
    "status block declares 22 canonical edges"
  check_status_line 'READY_TO_FUND_BOOLEAN_CHECKS = MODEL_ONLY' \
    "ReadyToFund boolean checks are declared MODEL_ONLY"
fi

echo
if [[ $failures -eq 0 ]]; then
  echo "ADJUDICATION_GUARD = PASS"
  exit 0
fi
echo "ADJUDICATION_GUARD = FAIL ($failures violation(s))" >&2
exit 1
