#!/usr/bin/env bash
set -euo pipefail

probe_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
production_root=$(realpath "$probe_dir/../../../../phase1-publication-dom")
expected_commit=67fe11c441c2b7801b6f70809ab58caa4804c22a
actual_commit=$(git -C "$production_root" rev-parse HEAD)

if [[ "$actual_commit" != "$expected_commit" ]]; then
    echo "wrong production commit: expected $expected_commit, found $actual_commit" >&2
    exit 1
fi
if [[ -n "$(git -C "$production_root" status --porcelain=v1 -uno)" ]]; then
    echo "production tracked files are dirty; refusing comparison" >&2
    exit 1
fi

probe_target_dir=${PROBE_TARGET_DIR:-"$probe_dir/target-production-exact"}
mkdir -p "$probe_target_dir"

printf 'PRODUCTION_COMMIT_ACTUAL\t%s\n' "$actual_commit"
rustc --version --verbose
cargo --version --verbose

CARGO_TARGET_DIR="$probe_target_dir" cargo test \
    --manifest-path "$production_root/Cargo.toml" \
    --offline \
    --locked \
    -p dom-adaptor \
    share_pop::tests::deterministic_proof_roundtrips_and_mutations_fail \
    -- \
    --exact \
    --nocapture

mapfile -t adaptor_rlibs < <(
    find "$probe_target_dir/debug/deps" -maxdepth 1 -type f -name 'libdom_adaptor-*.rlib' | sort
)
mapfile -t crypto_rlibs < <(
    find "$probe_target_dir/debug/deps" -maxdepth 1 -type f -name 'libdom_crypto-*.rlib' | sort
)
mapfile -t zeroize_rlibs < <(
    find "$probe_target_dir/debug/deps" -maxdepth 1 -type f -name 'libzeroize-*.rlib' | sort
)

if [[ ${#adaptor_rlibs[@]} -ne 1 || ${#crypto_rlibs[@]} -ne 1 || ${#zeroize_rlibs[@]} -ne 1 ]]; then
    echo "expected exactly one production rlib for dom-adaptor, dom-crypto, and zeroize" >&2
    printf 'dom-adaptor=%s dom-crypto=%s zeroize=%s\n' \
        "${#adaptor_rlibs[@]}" "${#crypto_rlibs[@]}" "${#zeroize_rlibs[@]}" >&2
    exit 1
fi

probe_binary="$probe_target_dir/share-pop-v2-production-probe"
rustc \
    --edition=2021 \
    "$probe_dir/src/main.rs" \
    -L "dependency=$probe_target_dir/debug/deps" \
    --extern "dom_adaptor=${adaptor_rlibs[0]}" \
    --extern "dom_crypto=${crypto_rlibs[0]}" \
    --extern "zeroize=${zeroize_rlibs[0]}" \
    -o "$probe_binary"

(
    cd "$probe_dir"
    "$probe_binary"
)
