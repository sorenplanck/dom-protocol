#!/usr/bin/env bash
#
# The single named exception to node byte-identity, and its death condition.
#
# Every one of the node's twenty-nine crates in this branch is byte-identical to
# release/mainnetv2@3008587340033fcfa784fbfbcf8f69c33a2d7514, with exactly one
# exception: crates/dom-integration-tests/tests/replay_determinism.rs, whose
# `side_chain_block_does_not_rewrite_canonical_tip_after_restart` carries a
# pre-existing defect of the release line.
#
# The defect: the test mines a canonical height-1 block and an independent
# height-1 competitor, then asserts ConnectResult::SideChain. Both blocks sit at
# height 1 on regtest with the same fixed target, so their total difficulty is
# equal by construction, and the node's own fork choice breaks an equal-work tie
# by the lexicographically smaller hash (crates/dom-chain/src/chain_state.rs,
# `is_better_fork_choice_tip`). The assertion therefore holds only when the
# competitor's hash happens to sort above the canonical tip's — a coin flip on
# the mined nonce. Measured on the release line itself, rebuilt with that
# commit's Cargo.toml and Cargo.lock: 8 failures in 16 runs.
#
# The fix makes the SCENARIO deterministic rather than the result conditional:
# it re-mines the competitor until it loses the tie-break, which is the scenario
# the test's name and its ten subsequent assertions already describe.
#
# This guard pins both sides so neither can drift in silence, and it is designed
# to FAIL on the day the node line adopts the same fix — at which point the
# exception is over and byte identity must be restored.
set -euo pipefail

REL=3008587340033fcfa784fbfbcf8f69c33a2d7514
PATH_IN_TREE=crates/dom-integration-tests/tests/replay_determinism.rs
MARKER='loses the equal-work tie-break'

# Pinned contents. The release side is the fact this exception is measured
# against; the working-tree side is the exact text that is meant to go to the
# node line unchanged.
SHA_RELEASE=a9aae799dad5556b4c8d883b5b6fbd2d2acbb2db1182430f1b28185ad1bd2738
SHA_FIXED=61e82510cad6780baa5b22bbec78a5d6a6e3afcbd13296af61dd40f65fffb670

fail() { printf '%s\n' "$@" >&2; exit 1; }

# The release commit is not in a shallow clone. Fetching it by SHA costs one
# commit and its trees. Fail closed if it cannot be obtained: a guard that
# quietly skips is not a guard.
if ! git cat-file -e "${REL}^{commit}" 2>/dev/null; then
  git fetch --depth=1 --quiet origin "$REL" 2>/dev/null || true
fi
git cat-file -e "${REL}^{commit}" 2>/dev/null || fail \
  "cannot reach the release commit ${REL}." \
  "This guard compares the working tree against the release line and refuses" \
  "to pass without it. Fetch it (git fetch --depth=1 origin ${REL}) and re-run."

release_blob=$(mktemp); trap 'rm -f "$release_blob"' EXIT
git show "${REL}:${PATH_IN_TREE}" > "$release_blob"

got_release=$(sha256sum "$release_blob" | cut -d' ' -f1)
got_fixed=$(sha256sum "$PATH_IN_TREE" | cut -d' ' -f1)

# 1. The release line still carries the defect, unrepaired.
if grep -qF "$MARKER" "$release_blob"; then
  fail \
    "THE NODE LINE HAS ADOPTED THE FIX — this exception is over." \
    "" \
    "${PATH_IN_TREE} at ${REL} now contains the tie-break selection." \
    "Restore byte identity: check the file out from the release line," \
    "  git checkout ${REL} -- ${PATH_IN_TREE}" \
    "delete this guard and its wiring in .github/workflows/ci.yml, and remove" \
    "the named exception from docs/interop/INJECTION-RECORD.md."
fi

# 2. The release blob is the one this exception was measured against.
[ "$got_release" = "$SHA_RELEASE" ] || fail \
  "the release-line file changed underneath this exception." \
  "  expected ${SHA_RELEASE}" \
  "  got      ${got_release}" \
  "Re-measure the defect against the new text before re-pinning."

# 3. The working tree carries the fix, and exactly the pinned text of it.
grep -qF "$MARKER" "$PATH_IN_TREE" || fail \
  "${PATH_IN_TREE} no longer carries the tie-break selection." \
  "Without it the test is a coin flip again (8 failures in 16 on the release line)."

[ "$got_fixed" = "$SHA_FIXED" ] || fail \
  "${PATH_IN_TREE} drifted from the pinned exception text." \
  "  expected ${SHA_FIXED}" \
  "  got      ${got_fixed}" \
  "The exception is ONE hunk. Anything else in this file is node code that must" \
  "stay byte-identical to the release line. Re-pin only with the coordinator's" \
  "decision, and update docs/interop/INJECTION-RECORD.md in the same commit."

# 4. The exception really is one hunk and nothing else.
hunks=$(diff "$release_blob" "$PATH_IN_TREE" | grep -c '^[0-9]' || true)
[ "$hunks" = "1" ] || fail \
  "the exception spans ${hunks} hunks, not 1." \
  "A second hunk means node code drifted beyond the named exception."

echo "node-test exception OK: 1 hunk, release line still unrepaired at ${REL:0:7}"
