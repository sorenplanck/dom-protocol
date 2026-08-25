#!/usr/bin/env bash
# Bind the Rust policy foundation to the signed NAR-DC-P1-007 bytes.
#
# check-normative-adjudication.sh proves the ratified document still says what
# it was signed saying. This guard proves the crate agrees with it: that the
# Rust edge table is the adjudicated one, in order, and that the roster rule is
# the exactly-two rule with its three distinct refusals.
#
# It fails closed. A source it cannot read is a failure, never a skip.
set -Eeuo pipefail

# Anchored to the workspace root, not to the git top level: in the monorepo
# these are different directories, and every path literal below is relative to
# the workspace the guarded crates belong to.
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

record="docs/specifications/normative/NAR-DC-P1-007-phase-state-participant-and-funding-authority-closure.en.md"
topology="crates/dom-scriptless-protocol/src/topology.rs"
roster="crates/dom-scriptless-protocol/src/roster.rs"

failures=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1" >&2; failures=$((failures + 1)); }

echo "== NAR-DC-P1-007 policy topology guard =="

missing=0
for source in "$record" "$topology" "$roster"; do
  if [[ ! -f "$source" ]]; then
    echo "  FAIL  required source is absent: $source" >&2
    missing=1
  fi
done
if [[ $missing -ne 0 ]]; then
  echo "POLICY_TOPOLOGY_GUARD = FAIL (absent source)" >&2
  exit 1
fi

# Adjudicated edges, read from the signed record's section 3.2 enumeration and
# bounded by the section 3.3 heading, in published order.
mapfile -t adjudicated < <(
  awk '/^### 3\.2 Decision$/{inside=1; next} /^### 3\.3 /{inside=0} inside' "$record" |
    grep -E '^[[:space:]]*[0-9]{1,2}[[:space:]]+[A-Za-z][A-Za-z0-9]*[[:space:]]+->[[:space:]]+[A-Za-z][A-Za-z0-9]*[[:space:]]*$' |
    sed -E 's/^[[:space:]]*[0-9]{1,2}[[:space:]]+//; s/[[:space:]]+->[[:space:]]+/ -> /; s/[[:space:]]+$//'
)

# Rust edges, read from the NORMATIVE_EDGES array. rustfmt may wrap a single
# tuple across several lines, so the array body is flattened before matching
# rather than parsed line by line.
#
# Comments are stripped BEFORE flattening. Deleting newlines destroys line
# structure, so a `//` comment survives flattening and its contents are then
# indistinguishable from code: a commented-out edge would be counted as
# implemented, and a commented-out edge plus a matching count constant would
# make a 21-edge compiled table report as a conforming 22. The trailing comma
# rustfmt leaves inside a wrapped tuple is optional in the pattern, because the
# single-line form does not have one.
mapfile -t implemented < <(
  awk '/pub const NORMATIVE_EDGES/{inside=1} inside{print} inside && /^\s*\];\s*$/{exit}' "$topology" |
    sed -E 's|//.*$||' |
    tr -d ' \n' |
    grep -oE '\(SessionPhaseV1::[A-Za-z0-9]+,SessionPhaseV1::[A-Za-z0-9]+,?\)' |
    sed -E 's/^\(SessionPhaseV1::([A-Za-z0-9]+),SessionPhaseV1::([A-Za-z0-9]+),?\)$/\1 -> \2/'
)

if [[ ${#adjudicated[@]} -eq 22 ]]; then
  pass "the signed record enumerates 22 edges"
else
  fail "the signed record enumerates ${#adjudicated[@]} edges, expected 22"
fi

if [[ ${#implemented[@]} -eq 22 ]]; then
  pass "NORMATIVE_EDGES declares 22 edges"
else
  fail "NORMATIVE_EDGES declares ${#implemented[@]} edges, expected 22"
fi

# Ordered comparison. A reordering is a divergence from the published table, so
# this deliberately does not sort either side: it catches missing, extra and
# reordered edges in one check.
if [[ ${#adjudicated[@]} -gt 0 ]] &&
  diff <(printf '%s\n' "${adjudicated[@]}") <(printf '%s\n' "${implemented[@]}") >/dev/null; then
  pass "NORMATIVE_EDGES equals the signed table exactly, in order"
else
  fail "NORMATIVE_EDGES diverges from the signed table"
  diff <(printf '%s\n' "${adjudicated[@]}") <(printf '%s\n' "${implemented[@]}") >&2 || true
fi

# The remaining edge checks are only meaningful once something was parsed. An
# empty parse already failed the count check above; reporting these as passes
# on top of it would make a transcript of nothing-parsed read like three
# successes.
if [[ ${#implemented[@]} -eq 0 ]]; then
  fail "no edge was parsed from NORMATIVE_EDGES; uniqueness and shortcut checks cannot run"
else
  duplicates="$(printf '%s\n' "${implemented[@]}" | sort | uniq -d)"
  if [[ -z "$duplicates" ]]; then
    pass "every implemented edge is unique"
  else
    fail "duplicate edge(s) in NORMATIVE_EDGES: $(printf '%s; ' $duplicates)"
  fi

  shortcut_found=0
  for shortcut in "TemplatesCommitted -> RefundSigned" "RefundSigned -> ClaimPrepared"; do
    if grep -Fxq "$shortcut" <<<"$(printf '%s\n' "${implemented[@]}")"; then
      fail "removed shortcut implemented: $shortcut"
      shortcut_found=1
    fi
  done
  [[ $shortcut_found -eq 0 ]] && pass "neither removed shortcut is implemented"
fi

# The roster rule: exactly two, with the three refusals the record requires to
# be distinguishable. Checking that the three names exist would only prove three
# identifiers are declared, so the constructor is required to return each one.
#
# Comments are stripped first. `ParticipantSetError::TooMany` appears in this
# module's own rustdoc, so an unscoped search finds the documentation and
# reports a refusal as returned even when the constructor no longer returns it.
roster_code="$(sed -E 's|//.*$||' "$roster")"

if grep -Eq '^pub const PARTICIPANT_COUNT: usize = 2;$' <<<"$roster_code"; then
  pass "PARTICIPANT_COUNT is exactly two"
else
  fail "PARTICIPANT_COUNT is not declared as exactly two"
fi

if grep -Eq '^[[:space:]]+\[first, second\] => \(first, second\),$' <<<"$roster_code"; then
  pass "the accept path admits exactly two identities"
else
  fail "the accept path does not admit exactly two identities"
fi

for variant in TooFew TooMany Duplicate; do
  if ! grep -Eq "^[[:space:]]+${variant}[[:space:]]*(\{|,)" <<<"$roster_code"; then
    fail "refusal $variant is missing from the taxonomy"
  elif ! grep -Fq "Err(ParticipantSetError::${variant}" <<<"$roster_code"; then
    fail "refusal $variant is declared but never returned by the constructor"
  else
    pass "refusal $variant is a distinct outcome the constructor returns"
  fi
done

echo
if [[ $failures -eq 0 ]]; then
  echo "POLICY_TOPOLOGY_GUARD = PASS"
  exit 0
fi
echo "POLICY_TOPOLOGY_GUARD = FAIL ($failures violation(s))" >&2
exit 1
