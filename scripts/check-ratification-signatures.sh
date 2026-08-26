#!/usr/bin/env bash
# Verify every transported minisign signature against the operator's key.
#
# The signatures travelled with the normative records; the key that verifies
# them lived in `laboratory/`, which did not. A signature without the means to
# check it is decoration, so the key travels too — only the `.pub`, nothing
# else from `laboratory/`.
#
# This guard EXECUTES `minisign -V`. It does not assert that the signatures
# verify; it verifies them, every run.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

key="docs/interop/ratifications/operator-signing-key.pub"
if [[ ! -f "$key" ]]; then
    echo "FAIL the operator signing key is missing: $key" >&2
    echo "     Without it the signatures in this repository cannot be checked." >&2
    exit 1
fi

if ! command -v minisign >/dev/null 2>&1; then
    echo "FAIL minisign is not installed; signatures cannot be verified" >&2
    echo "     This is a hard failure, not a skip: an unverifiable signature" >&2
    echo "     must never read as a verified one." >&2
    exit 1
fi

# The exact count is pinned. A signature that disappears is as much a change as
# one that fails, and a silent zero would otherwise pass this loop.
expected_signatures=14

signatures="$(git ls-files '*.minisig' | sort)"
count="$(printf '%s\n' "$signatures" | grep -c . || true)"
if [[ "$count" -ne "$expected_signatures" ]]; then
    echo "FAIL expected $expected_signatures signatures, found $count" >&2
    exit 1
fi

status=0
while IFS= read -r sig; do
    [[ -z "$sig" ]] && continue
    signed="${sig%.minisig}"
    if [[ ! -f "$signed" ]]; then
        echo "FAIL signed document missing for $sig" >&2
        status=1
        continue
    fi
    if ! minisign -V -p "$key" -m "$signed" >/dev/null 2>&1; then
        echo "FAIL signature does not verify: $signed" >&2
        status=1
    fi
done <<<"$signatures"

if [[ $status -ne 0 ]]; then
    echo "RATIFICATION_SIGNATURES = FAIL" >&2
    exit 1
fi

echo "RATIFICATION_SIGNATURES = PASS ($count verified)"
