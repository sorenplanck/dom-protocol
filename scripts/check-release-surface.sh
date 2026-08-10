#!/usr/bin/env bash
#
# Release-artifact surface gate for DOM Protocol.
#
# WHY THIS EXISTS
# ---------------
# Several capabilities in this workspace exist ONLY for tests, fuzzing, and
# lab/evidence work, and are gated behind default-off Cargo features:
#
#   * dom-crypto/test-helpers  -> exports `bp2_test_only_prove_legacy_single_with_nonce`,
#                                 a nonce-controlled legacy-format range-proof prover;
#   * dom-faucet/shield-probe  -> re-exports the private payment-request parser;
#   * labs/dom-bp-migration-lab, crates/*/fuzz -> lab and fuzz harnesses.
#
# "Default-off" was, until this gate existed, a documented requirement and
# nothing more: no CI step ever inspected a built release artifact to confirm
# that the shipped bytes are free of them. A documented requirement is not an
# implemented one. This script inspects real, freshly built release artifacts.
#
# WHAT IT CHECKS
# --------------
#   A. Feature graph  -- `cargo tree --locked -e features,normal,build,no-dev`
#      for each release package must not enable any forbidden feature and must
#      not pull in any forbidden (test-only / fuzz / lab / bench) package.
#   B. Symbols        -- `nm` over every artifact `cargo build --release`
#      actually produced (binaries and rlibs, discovered from cargo's own JSON
#      message stream, never guessed from a path) must contain no forbidden
#      symbol substring.
#
# FAIL-CLOSED DOCTRINE
# --------------------
# A check that cannot run is a FAILURE, never a skip:
#   * a missing tool (cargo, nm, python3)                    -> exit 1
#   * a failed release build                                 -> exit 1
#   * a package that produced zero inspectable artifacts     -> exit 1
#   * an artifact from which nm reads zero symbols           -> exit 1
#     (stripped or bitcode-only artifacts are NOT evidence)
#   * the forbidden-symbol matcher failing its own self-test -> exit 1
#
# Usage:
#   scripts/check-release-surface.sh [--package NAME]...
#
# Defaults to the DOM scriptless-contract library surface
# (dom-adaptor, dom-crypto) when no --package is given.
#
# Environment:
#   CARGO   override the cargo binary (default: cargo)
#   NM      override the symbol reader (default: llvm-nm if present, else nm)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

CARGO="${CARGO:-cargo}"

PACKAGES=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --package|-p)
            [ "$#" -ge 2 ] || { echo "FATAL: --package needs a value" >&2; exit 1; }
            PACKAGES+=("$2")
            shift 2
            ;;
        --help|-h)
            sed -n '2,40p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            printf 'FATAL: unknown argument %s\n' "$1" >&2
            exit 1
            ;;
    esac
done
if [ "${#PACKAGES[@]}" -eq 0 ]; then
    PACKAGES=(dom-adaptor dom-crypto)
fi

# ── Forbidden surfaces ───────────────────────────────────────────────────────
# Cargo features that must never be enabled in a release graph.
FORBIDDEN_FEATURES=(
    test-helpers
    test_helpers
    shield-probe
    shield_probe
    fault-injection
    nonce-injection
    evidence-only
    lab
    fuzzing
    unstable-test-api
)

# Packages that must never appear in a release (non-dev) dependency graph.
FORBIDDEN_PACKAGES=(
    dom-bp-migration-lab
    dom-adaptor-fuzz
    dom-chain-fuzz
    dom-store-fuzz
    dom-tx-fuzz
    dom-wallet-fuzz
    libfuzzer-sys
    honggfuzz
    afl
    proptest
    criterion
    arbitrary
)

# Symbol substrings that betray a test-only / lab / fault-injection entry point
# compiled into the artifact. Matched case-insensitively against both the raw
# and the demangled symbol tables.
#
# NOTE deliberately absent: plain "nonce". Deterministic nonce-taking provers
# such as `range_proof_prove_with_nonce` are ratified PRODUCTION API; only
# explicit *injection* shapes are forbidden.
FORBIDDEN_SYMBOL_PATTERNS=(
    'test_only'
    'test_helper'
    'testhelper'
    'shield_probe'
    'fault_inject'
    'inject_fault'
    'nonce_inject'
    'inject_nonce'
    'fuzz_target'
    'libfuzzer'
    'rust_fuzzer'
    '__sanitizer_cov'
    'bp_migration_lab'
    'evidence_only'
    'backdoor'
)

failures=0
fail() {
    printf 'FAIL: %s\n' "$*" >&2
    failures=$((failures + 1))
}

# Probe INVOCABILITY, not mere presence. `command -v cargo` can succeed while
# `cargo --version` fails with "the 'cargo' binary is not applicable to the
# 'stable-x86_64-unknown-linux-gnu' toolchain" (rustup mid-update, a broken
# shim, or a shell function shadowing the real binary). A gate that only checks
# presence would then fail later, confusingly, or worse: appear to pass.
require_tool() {
    local tool="$1"
    local probe="${2:---version}"
    if ! command -v "${tool}" >/dev/null 2>&1; then
        printf 'FATAL: required tool %s not found; this gate cannot run and therefore fails.\n' "${tool}" >&2
        exit 1
    fi
    if ! "${tool}" "${probe}" >/dev/null 2>&1; then
        printf 'FATAL: %s is present but not invocable (%s %s failed); this gate cannot run and therefore fails.\n' \
            "${tool}" "${tool}" "${probe}" >&2
        "${tool}" "${probe}" >&2 || true
        exit 1
    fi
}

require_tool "${CARGO}"
require_tool python3

if [ -n "${NM:-}" ]; then
    :
elif command -v llvm-nm >/dev/null 2>&1; then
    NM=llvm-nm
elif command -v nm >/dev/null 2>&1; then
    NM=nm
else
    echo 'FATAL: neither llvm-nm nor nm is available; the symbol scan cannot run and therefore fails.' >&2
    exit 1
fi

echo "=== DOM release-surface gate ==="
echo "repo root: ${REPO_ROOT}"
echo "packages : ${PACKAGES[*]}"
echo "symbol reader: ${NM} ($(${NM} --version 2>&1 | head -n 1))"
"${CARGO}" --version
echo

# Build the alternation once; reused by the scan and by its self-test.
symbol_regex="$(printf '%s|' "${FORBIDDEN_SYMBOL_PATTERNS[@]}")"
symbol_regex="${symbol_regex%|}"

# ── 0. Detector self-test ────────────────────────────────────────────────────
# A silently broken matcher would turn this gate into a rubber stamp. Prove the
# matcher still flags every forbidden pattern before trusting a clean result.
echo "--- 0. forbidden-symbol detector self-test ---"
for pattern in "${FORBIDDEN_SYMBOL_PATTERNS[@]}"; do
    canary="_ZN9dom_crypto_SELFTEST_${pattern}_canary17hE"
    if ! printf '%s\n' "${canary}" | grep -qiE "${symbol_regex}"; then
        printf 'FATAL: detector self-test failed for pattern %s; refusing to certify.\n' "${pattern}" >&2
        exit 1
    fi
done
# And prove it does NOT flag the ratified production nonce API.
for benign in \
    'dom_crypto::range_proof::prove_bytes_with_nonce' \
    'dom_adaptor::raw_nonce_reveal_v1' \
    'dom_crypto::bulletproof_bp::bp_verify'
do
    if printf '%s\n' "${benign}" | grep -qiE "${symbol_regex}"; then
        printf 'FATAL: detector self-test false-positives on ratified API %s; refusing to certify.\n' "${benign}" >&2
        exit 1
    fi
done
printf 'OK   detector recognises all %s forbidden patterns and none of the ratified ones.\n' "${#FORBIDDEN_SYMBOL_PATTERNS[@]}"
echo

# ── A. Release feature graph ─────────────────────────────────────────────────
echo "--- A. release feature graph (cargo tree --locked, non-dev) ---"
tree_dir="$(mktemp -d)"
trap 'rm -rf "${tree_dir}"' EXIT

for pkg in "${PACKAGES[@]}"; do
    tree_out="${tree_dir}/${pkg}.tree"
    if ! "${CARGO}" tree --locked -p "${pkg}" -e features,normal,build,no-dev > "${tree_out}" 2>"${tree_out}.err"; then
        cat "${tree_out}.err" >&2
        fail "${pkg}: cargo tree failed; the feature graph could not be inspected."
        continue
    fi

    pkg_bad=0
    for feat in "${FORBIDDEN_FEATURES[@]}"; do
        # cargo tree renders feature edges as: `feature "test-helpers"`.
        if grep -qE "feature \"${feat}\"" "${tree_out}"; then
            grep -nE "feature \"${feat}\"" "${tree_out}" >&2
            fail "${pkg}: forbidden feature \"${feat}\" is enabled in the release graph."
            pkg_bad=1
        fi
    done
    for bad_pkg in "${FORBIDDEN_PACKAGES[@]}"; do
        if grep -qE "^[^a-zA-Z0-9_-]*${bad_pkg} v" "${tree_out}"; then
            grep -nE "^[^a-zA-Z0-9_-]*${bad_pkg} v" "${tree_out}" >&2
            fail "${pkg}: forbidden package \"${bad_pkg}\" is in the release (non-dev) graph."
            pkg_bad=1
        fi
    done
    if [ "${pkg_bad}" -eq 0 ]; then
        printf 'OK   %-12s release feature graph clean (%s lines inspected).\n' \
            "${pkg}" "$(wc -l < "${tree_out}" | tr -d ' ')"
    fi
done
echo

# ── B. Built release artifacts + symbol scan ─────────────────────────────────
echo "--- B. release artifacts (cargo build --release --locked) ---"
build_args=(build --release --locked --message-format=json-render-diagnostics)
for pkg in "${PACKAGES[@]}"; do
    build_args+=(-p "${pkg}")
done

build_json="${tree_dir}/build.json"
if ! "${CARGO}" "${build_args[@]}" > "${build_json}"; then
    echo 'FATAL: release build failed; there is no artifact to certify.' >&2
    exit 1
fi

# A2. Features cargo ACTUALLY compiled. `cargo tree` above reports a resolved
# graph; the compiler-artifact stream reports what each unit was built with, so
# this is the authoritative feature evidence for the artifacts scanned below.
echo "--- A2. features actually compiled into the release units ---"
feature_hits="${tree_dir}/compiled-features.bad"
if ! python3 - "${build_json}" "${FORBIDDEN_FEATURES[@]}" > "${feature_hits}" <<'PY'
import json
import sys

build_json = sys.argv[1]
forbidden = {f.replace("_", "-").lower() for f in sys.argv[2:]}
units = 0
bad = []
with open(build_json, "r", encoding="utf-8", errors="replace") as handle:
    for line in handle:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact":
            continue
        units += 1
        name = (msg.get("target") or {}).get("name", "?")
        for feat in msg.get("features") or []:
            if feat.replace("_", "-").lower() in forbidden:
                bad.append(f"{name}: forbidden feature {feat!r} was compiled in")
sys.stderr.write(f"     {units} compiler-artifact units inspected.\n")
if units == 0:
    sys.stderr.write("     FATAL: no compiler-artifact units in the build stream.\n")
    sys.exit(2)
for line in bad:
    print(line)
PY
then
    echo 'FATAL: could not read the compiled feature set from the build stream.' >&2
    exit 1
fi
if [ -s "${feature_hits}" ]; then
    cat "${feature_hits}" >&2
    fail "forbidden feature(s) compiled into the release build (see above)."
else
    printf 'OK   no forbidden feature compiled into any release unit.\n'
fi
echo

for pkg in "${PACKAGES[@]}"; do
    artifacts_file="${tree_dir}/${pkg}.artifacts"
    python3 - "${build_json}" "${pkg}" > "${artifacts_file}" <<'PY'
import json
import sys

build_json, package = sys.argv[1], sys.argv[2]
seen = []
with open(build_json, "r", encoding="utf-8", errors="replace") as handle:
    for line in handle:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact":
            continue
        target = msg.get("target") or {}
        if target.get("name", "").replace("-", "_") != package.replace("-", "_"):
            continue
        kinds = set(target.get("kind") or [])
        if not kinds & {"bin", "lib", "rlib", "cdylib", "staticlib", "dylib"}:
            continue
        for path in msg.get("filenames") or []:
            if path.endswith((".rmeta", ".d")):
                continue
            if path not in seen:
                seen.append(path)
for path in seen:
    print(path)
PY

    if [ ! -s "${artifacts_file}" ]; then
        fail "${pkg}: cargo produced no inspectable release artifact (bin/rlib); nothing to certify."
        continue
    fi

    while IFS= read -r artifact; do
        [ -n "${artifact}" ] || continue
        if [ ! -f "${artifact}" ]; then
            fail "${pkg}: artifact ${artifact} reported by cargo does not exist on disk."
            continue
        fi

        raw_syms="${tree_dir}/$(basename "${artifact}").syms"
        if ! "${NM}" --no-sort "${artifact}" > "${raw_syms}" 2>"${raw_syms}.err"; then
            cat "${raw_syms}.err" >&2
            fail "${pkg}: ${NM} could not read symbols from ${artifact}."
            continue
        fi
        # Demangled view too: Rust symbols hide the readable path inside the
        # mangled name in some encodings (v0 in particular).
        "${NM}" --no-sort --demangle "${artifact}" >> "${raw_syms}" 2>/dev/null || true

        sym_count="$(grep -cE '^[0-9a-fA-F ]* [A-Za-z] ' "${raw_syms}" || true)"
        if [ "${sym_count}" -eq 0 ]; then
            fail "${pkg}: zero symbols readable from ${artifact} (stripped or bitcode-only artifact is not evidence)."
            continue
        fi

        hits="$(grep -iE "${symbol_regex}" "${raw_syms}" || true)"
        if [ -n "${hits}" ]; then
            printf '%s\n' "${hits}" | head -n 40 >&2
            fail "${pkg}: forbidden symbol(s) present in ${artifact}."
        else
            printf 'OK   %-12s %s: %s symbols, no forbidden surface.\n' \
                "${pkg}" "$(basename "${artifact}")" "${sym_count}"
        fi
    done < "${artifacts_file}"
done
echo

# ── Verdict ──────────────────────────────────────────────────────────────────
if [ "${failures}" -ne 0 ]; then
    printf '=== RELEASE SURFACE GATE: FAILED (%s check(s)) ===\n' "${failures}" >&2
    exit 1
fi
echo '=== RELEASE SURFACE GATE: PASSED ==='
