#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 DOM_REPOSITORY WALLET_REPOSITORY" >&2
    exit 64
fi

dom_candidate="$(realpath -- "$1")"
wallet_candidate="$(realpath -- "$2")"
readonly dom_candidate
readonly wallet_candidate
readonly official_dom="/home/leonardov/dom-release"
readonly official_wallet="/home/leonardov/dom-wallet-v3"

for candidate in "$dom_candidate" "$wallet_candidate"; do
    if [[ "$candidate" == "$official_dom" || "$candidate" == "$official_wallet" ]]; then
        echo "refusing to audit an official read-only source as an integration candidate: $candidate" >&2
        exit 65
    fi
    git -C "$candidate" rev-parse --is-inside-work-tree >/dev/null
    if [[ -n "$(git -C "$candidate" status --porcelain --untracked-files=no)" ]]; then
        echo "refusing candidate with tracked changes: $candidate" >&2
        git -C "$candidate" status --short --untracked-files=no >&2
        exit 66
    fi
done

print_identity() {
    local candidate="$1"
    echo "REPOSITORY=$candidate"
    echo "BRANCH=$(git -C "$candidate" branch --show-current || true)"
    echo "HEAD=$(git -C "$candidate" rev-parse HEAD)"
    echo "TREE=$(git -C "$candidate" rev-parse 'HEAD^{tree}')"
    echo "TRACKED_STATUS=clean"
    if [[ -f "$candidate/Cargo.lock" ]]; then
        echo "LOCKFILE_SHA256=$(sha256sum "$candidate/Cargo.lock" | awk '{print $1}')"
    else
        echo "LOCKFILE_SHA256=ABSENT"
    fi
}

echo "SECTION=identity"
print_identity "$dom_candidate"
print_identity "$wallet_candidate"

echo "SECTION=dom-adaptor-direct-dependencies"
(
    cd "$dom_candidate"
    cargo metadata --format-version 1 --locked \
        | python3 -c '
import json
import sys

metadata = json.load(sys.stdin)
packages = [package for package in metadata["packages"] if package["name"] == "dom-adaptor"]
if len(packages) != 1:
    raise SystemExit(f"expected exactly one dom-adaptor package, found {len(packages)}")
for dependency in sorted(packages[0]["dependencies"], key=lambda item: (item["name"], str(item["kind"]))):
    print(
        "{}\tkind={}\toptional={}".format(
            dependency["name"], dependency["kind"], dependency["optional"]
        )
    )
'
)

echo "SECTION=dom-adaptor-feature-graph"
(
    cd "$dom_candidate"
    cargo tree -p dom-adaptor -e features --locked
)

echo "SECTION=wallet-vault-reverse-dependencies"
(
    cd "$wallet_candidate"
    cargo tree -i dom-wallet-scriptless-vault -e features --locked
)

echo "SECTION=machine-local-manifest-paths"
if rg -n --glob 'Cargo.toml' --glob 'Cargo.lock' \
    '(/home/leonardov|path[[:space:]]*=[[:space:]]*"/|path[[:space:]]*=[[:space:]]*"\.\./.*worktrees)' \
    "$dom_candidate" "$wallet_candidate"; then
    echo "RESULT=FINDING"
else
    echo "RESULT=no match"
fi

echo "SECTION=bypass-names"
if rg -n -i \
    '(skip[_-]?(vault|witness|persist)|bypass[_-]?(vault|witness|persist)|caller[_-]?(receipt|witness[_-]?accepted|storage[_-]?success)|Box[[:space:]]*<[[:space:]]*dyn[[:space:]]+NonceVaultV1)' \
    "$dom_candidate/crates/dom-adaptor" "$wallet_candidate"; then
    echo "RESULT=REVIEW_REQUIRED"
else
    echo "RESULT=no lexical match"
fi

echo "SECTION=raw-secret-and-partial-public-surface"
rg -n \
    'pub([[:space:]]*\([^)]*\))?[[:space:]]+(fn|struct|enum|trait|type|use).*(SecretNonce|NonceSecret|derive.*nonce|raw.*nonce|raw.*reveal|raw.*partial|PartialSignature)' \
    "$dom_candidate/crates/dom-adaptor" || true

echo "SECTION=capability-constructors-and-conversions"
rg -n \
    '(ExposureCapability|ExposurePermit|AuthorizedExposure|PreparedExposure|from_bytes|into_bytes|as_bytes|Serialize|Deserialize|Clone|Copy|Debug|Display)' \
    "$dom_candidate/crates/dom-adaptor" "$wallet_candidate" || true

echo "SECTION=unsafe-in-integration-boundary"
rg -n '\bunsafe\b' "$dom_candidate/crates/dom-adaptor" "$wallet_candidate/crates/dom-wallet-scriptless-vault" || true

echo "SECTION=forbidden-project-references"
if rg -n -i '(DL2P|rfc000|legacy L2)' \
    "$dom_candidate/crates/dom-adaptor" "$wallet_candidate/crates/dom-wallet-scriptless-vault"; then
    echo "RESULT=REVIEW_REQUIRED"
else
    echo "RESULT=no lexical match"
fi

echo "SECTION=git-diff-check"
git -C "$dom_candidate" diff --check
git -C "$wallet_candidate" diff --check
echo "RESULT=complete"
