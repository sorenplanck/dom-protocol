#!/usr/bin/env bash
#
# Frozen doctest inventory for the DOM API-bypass compile_fail proofs.
#
# WHY THIS EXISTS
# ---------------
# The `compile_fail` doctests in dom-adaptor and dom-crypto are the largest
# body of API-bypass evidence in this repository: each one proves that a
# sealed constructor, a crate-private capability, or a test-only escape hatch
# CANNOT be reached from downstream code. They are the evidence the Phase 1
# scriptless-contract subset depends on.
#
# `cargo build --all-targets`, `cargo clippy --all-targets` and
# `cargo test --all-targets` do NOT compile or run doctests: `--all-targets`
# is lib+bins+tests+benches+examples and explicitly EXCLUDES `--doc`. Without
# an explicit gate these proofs can be deleted, renamed, or silently turned
# into ```ignore blocks and every CI job stays green.
#
# This script therefore freezes three numbers and fails closed on all of them:
#
#   1. the number of ```compile_fail doc fences present in the source,
#      per crate (catches deletion / demotion to ```ignore or ```text);
#   2. the number of doctests actually EXECUTED by `cargo test --doc`
#      (catches a fence that is present but no longer collected as a test);
#   3. the number of bare `#[ignore]` attributes, which must be zero
#      (an ignored test with no reason is an undocumented hole in the gate).
#
# FAIL-CLOSED DOCTRINE
# --------------------
# A check that cannot run is a FAILURE, never a skip. A missing crate, a
# missing `cargo`, an unparseable `cargo test --doc` summary, an ignored or
# failed doctest — every one of those exits non-zero.
#
# Usage:
#   scripts/check-doctest-inventory.sh
#
# Environment:
#   CARGO   override the cargo binary (default: cargo)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

CARGO="${CARGO:-cargo}"

# ── Frozen expectations ──────────────────────────────────────────────────────
# Update these ONLY together with the doctests themselves, in the same commit,
# with the reason stated in the commit message. A drop here is a loss of
# API-bypass evidence, not a cleanup.
AUDITED_CRATES=(dom-adaptor dom-crypto)

frozen_compile_fail_for() {
    case "$1" in
        dom-adaptor) echo 32 ;;
        dom-crypto)  echo 1 ;;
        *) return 1 ;;
    esac
}

FROZEN_COMPILE_FAIL_TOTAL=33

failures=0
fail() {
    printf 'FAIL: %s\n' "$*" >&2
    failures=$((failures + 1))
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'FATAL: required tool %s not found; this gate cannot run and therefore fails.\n' "$1" >&2
        exit 1
    }
}

require_tool "${CARGO}"
require_tool grep

echo "=== DOM doctest inventory gate ==="
echo "repo root: ${REPO_ROOT}"
"${CARGO}" --version
echo

# ── 1. Static ```compile_fail fence inventory ────────────────────────────────
echo "--- 1. static compile_fail fence count ---"
static_total=0
for crate in "${AUDITED_CRATES[@]}"; do
    crate_src="crates/${crate}/src"
    if [ ! -d "${crate_src}" ]; then
        printf 'FATAL: %s does not exist; the audited crate set is stale.\n' "${crate_src}" >&2
        exit 1
    fi

    expected="$(frozen_compile_fail_for "${crate}")"
    # Doc-comment fences only (`///` or `//!`), so ordinary code strings that
    # happen to contain the token cannot inflate the count.
    observed="$(grep -rn --include='*.rs' -E '^[[:space:]]*//[/!].*```compile_fail' "${crate_src}" | wc -l | tr -d ' ')"
    static_total=$((static_total + observed))

    if [ "${observed}" -eq "${expected}" ]; then
        printf 'OK   %-12s compile_fail fences: %s (frozen %s)\n' "${crate}" "${observed}" "${expected}"
    else
        fail "${crate}: ${observed} compile_fail doc fences, frozen expectation is ${expected}."
    fi
done

if [ "${static_total}" -eq "${FROZEN_COMPILE_FAIL_TOTAL}" ]; then
    printf 'OK   total compile_fail fences: %s (frozen %s)\n' "${static_total}" "${FROZEN_COMPILE_FAIL_TOTAL}"
else
    fail "total compile_fail doc fences ${static_total}, frozen expectation is ${FROZEN_COMPILE_FAIL_TOTAL}."
fi
echo

# ── 2. Executed doctest count ────────────────────────────────────────────────
# The static count proves the text is present; only execution proves the
# compile_fail assertions still hold (i.e. the sealed item is still sealed).
echo "--- 2. executed doctest count (cargo test --doc --locked) ---"
executed_total=0
doc_log_dir="$(mktemp -d)"
trap 'rm -rf "${doc_log_dir}"' EXIT

for crate in "${AUDITED_CRATES[@]}"; do
    expected="$(frozen_compile_fail_for "${crate}")"
    log="${doc_log_dir}/${crate}.log"

    if ! "${CARGO}" test --doc -p "${crate}" --locked > "${log}" 2>&1; then
        cat "${log}" >&2
        fail "${crate}: cargo test --doc exited non-zero."
        continue
    fi

    # `test result: ok. N passed; M failed; K ignored; ...`
    summary="$(grep -E '^test result:' "${log}" | tail -n 1 || true)"
    if [ -z "${summary}" ]; then
        cat "${log}" >&2
        fail "${crate}: no 'test result:' summary in cargo test --doc output (unparseable; failing closed)."
        continue
    fi

    passed="$(printf '%s' "${summary}" | sed -nE 's/.* ([0-9]+) passed.*/\1/p')"
    failed="$(printf '%s' "${summary}" | sed -nE 's/.* ([0-9]+) failed.*/\1/p')"
    ignored="$(printf '%s' "${summary}" | sed -nE 's/.* ([0-9]+) ignored.*/\1/p')"

    if [ -z "${passed}" ] || [ -z "${failed}" ] || [ -z "${ignored}" ]; then
        printf 'summary line was: %s\n' "${summary}" >&2
        fail "${crate}: could not parse the doctest summary (failing closed)."
        continue
    fi

    executed_total=$((executed_total + passed))

    if [ "${failed}" -ne 0 ]; then
        fail "${crate}: ${failed} doctest(s) failed."
    fi
    if [ "${ignored}" -ne 0 ]; then
        fail "${crate}: ${ignored} doctest(s) ignored; an ignored API-bypass proof proves nothing."
    fi
    if [ "${passed}" -eq "${expected}" ]; then
        printf 'OK   %-12s doctests executed: %s (frozen %s)\n' "${crate}" "${passed}" "${expected}"
    else
        fail "${crate}: ${passed} doctests executed, frozen expectation is ${expected}."
    fi
done

if [ "${executed_total}" -eq "${FROZEN_COMPILE_FAIL_TOTAL}" ]; then
    printf 'OK   total doctests executed: %s (frozen %s)\n' "${executed_total}" "${FROZEN_COMPILE_FAIL_TOTAL}"
else
    fail "total doctests executed ${executed_total}, frozen expectation is ${FROZEN_COMPILE_FAIL_TOTAL}."
fi
echo

# ── 3. Zero bare #[ignore] ───────────────────────────────────────────────────
# `#[ignore]` without a reason is a test that silently does not run. Every
# ignored test in the audited crates must state why, in-source, so the gate
# is auditable without archaeology.
echo "--- 3. zero bare #[ignore] in audited crates ---"
bare_ignores="$(grep -rn --include='*.rs' -E '^[[:space:]]*#\[ignore\][[:space:]]*$' \
    "${AUDITED_CRATES[@]/#/crates/}" || true)"
if [ -n "${bare_ignores}" ]; then
    printf '%s\n' "${bare_ignores}" >&2
    bare_count="$(printf '%s\n' "${bare_ignores}" | wc -l | tr -d ' ')"
    fail "${bare_count} bare #[ignore] attribute(s); use #[ignore = \"<reason>\"]."
else
    echo 'OK   no bare #[ignore] attributes.'
fi

all_ignores="$(grep -rn --include='*.rs' -E '^[[:space:]]*#\[ignore' \
    "${AUDITED_CRATES[@]/#/crates/}" || true)"
if [ -n "${all_ignores}" ]; then
    echo 'Ignored tests present (each must carry a reason):'
    printf '%s\n' "${all_ignores}"
else
    echo 'No #[ignore] attributes at all in the audited crates.'
fi
echo

# ── Verdict ──────────────────────────────────────────────────────────────────
if [ "${failures}" -ne 0 ]; then
    printf '=== DOCTEST INVENTORY GATE: FAILED (%s check(s)) ===\n' "${failures}" >&2
    exit 1
fi
echo '=== DOCTEST INVENTORY GATE: PASSED ==='
