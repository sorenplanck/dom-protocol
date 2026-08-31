#!/usr/bin/env bash
# Layer-scoped local CI with explicit static, offline and live-local modes.
set -uo pipefail
export PYTHONDONTWRITEBYTECODE=1

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo="$(CDPATH='' cd -- "$script_dir/.." && pwd -P)"
mode="${1:---offline}"
failures=0

# Duplicated deliberately: the publication gate must not trust a mutable
# classification returned by the Python scanner without comparing it to the
# operator-approved mainnet node snapshot.
readonly -a OFFICIAL_NODE_MEMBERS=(
  crates/dom-agent-runner
  crates/dom-chain
  crates/dom-cli
  crates/dom-config
  crates/dom-consensus
  crates/dom-core
  crates/dom-crypto
  crates/dom-explorer
  crates/dom-faucet
  crates/dom-integration-tests
  crates/dom-mempool
  crates/dom-node
  crates/dom-pmmr
  crates/dom-pow
  crates/dom-rpc
  crates/dom-serialization
  crates/dom-slate
  crates/dom-store
  crates/dom-test-runner
  crates/dom-test-vectors
  crates/dom-tx
  crates/dom-wallet
  crates/dom-wallet-app
  crates/dom-wallet-core-api
  crates/dom-wallet-crypto
  crates/dom-wallet-keys
  crates/dom-wallet-recovery
  crates/dom-wallet2
  crates/dom-wire
)

usage() {
  cat <<'EOF'
usage: scripts/ci_local.sh [--static|--offline|--live-local]

  --static      Python/shell tests and source-policy guards; never runs Cargo.
  --offline     --static plus locked layer Cargo gates with networking disabled.
  --live-local  --offline plus the contract release gate and disposable local
                Anvil and Bitcoin Core Regtest end-to-end runs.

No mode contacts a public chain. Live execution is opt-in.
EOF
}

record_failure() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_command() {
  local command_name="$1"
  if command -v "$command_name" >/dev/null 2>&1; then
    return 0
  fi
  record_failure "required command is absent: $command_name"
  return 1
}

run_gate() {
  local label="$1"
  shift
  printf '\n== %s ==\n' "$label"
  if "$@"; then
    printf 'PASS: %s\n' "$label"
    return 0
  else
    local status=$?
    printf 'FAIL: %s (exit %d)\n' "$label" "$status" >&2
    failures=$((failures + 1))
    return 1
  fi
}

run_python_guard_tests() {
  python3 -B "$script_dir/tests/test_absorption_manifest.py" -v &&
    python3 -B "$script_dir/tests/test_guard_layer_policy.py" -v &&
    python3 -B "$script_dir/tests/test_production_readiness_manifest.py" -v
}

check_new_shell_syntax() {
  bash -n "$script_dir/guards.sh" &&
    bash -n "$script_dir/ci_local.sh" &&
    bash -n "$script_dir/check-authorship.sh"
}

check_publication_boundary() {
  local publication_ref
  if ! publication_ref="$(git -C "$repo" rev-parse --verify --quiet 'origin/mainnetswap^{commit}')"; then
    printf '%s\n' 'origin/mainnetswap is unavailable as the publication reference' >&2
    return 1
  fi
  if ! git -C "$repo" merge-base --is-ancestor "$publication_ref" HEAD; then
    printf '%s\n' 'origin/mainnetswap is not an ancestor of HEAD' >&2
    return 1
  fi

  local node_output
  if ! node_output="$(python3 -B "$script_dir/guard_layer_policy.py" \
      --root "$repo" --print-node-members)"; then
    printf '%s\n' 'could not derive the frozen node member set' >&2
    return 1
  fi
  local -a node_members=()
  mapfile -t node_members <<<"$node_output"
  if ((${#node_members[@]} != ${#OFFICIAL_NODE_MEMBERS[@]})); then
    printf '%s\n' 'policy scanner node set differs from the official snapshot' >&2
    return 1
  fi
  local index
  for ((index = 0; index < ${#OFFICIAL_NODE_MEMBERS[@]}; index++)); do
    if [[ "${node_members[index]}" != "${OFFICIAL_NODE_MEMBERS[index]}" ]]; then
      printf '%s\n' 'policy scanner node set differs from the official snapshot' >&2
      return 1
    fi
  done
  local node_member
  for node_member in "${node_members[@]}"; do
    if [[ ! "$node_member" =~ ^crates/[A-Za-z0-9_/-]+$ || "$node_member" == *../* ]]; then
      printf '%s\n' 'policy scanner returned an invalid node member path' >&2
      return 1
    fi
  done
  if ((${#node_members[@]} == 0)); then
    printf '%s\n' 'policy scanner returned an empty node member set' >&2
    return 1
  fi
  for node_member in "${OFFICIAL_NODE_MEMBERS[@]}"; do
    if ! git -C "$repo" cat-file -e "$publication_ref:$node_member/Cargo.toml" 2>/dev/null; then
      printf 'official node member is absent from origin/mainnetswap: %s\n' \
        "$node_member" >&2
      return 1
    fi
  done
  if ! git -C "$repo" diff --quiet "$publication_ref" -- "${node_members[@]}"; then
    printf '%s\n' 'frozen node members differ from origin/mainnetswap' >&2
    return 1
  fi
  local untracked_node
  untracked_node="$(git -C "$repo" ls-files --others --exclude-standard -- "${node_members[@]}")"
  if [[ -n "$untracked_node" ]]; then
    printf 'untracked content exists under frozen node members:\n%s\n' "$untracked_node" >&2
    return 1
  fi
  DOM_AUTHORSHIP_BASELINE="$publication_ref" "$script_dir/check-authorship.sh" HEAD
}

run_static() {
  local initial_failures="$failures"
  local command_name
  for command_name in bash git minisign python3 shellcheck; do
    require_command "$command_name" || true
  done
  if ((failures != initial_failures)); then
    return 1
  fi
  if [[ "$mode" == "--static" ]]; then
    for command_name in cargo rustc rustup forge anvil cast bitcoin-cli bitcoind; do
      if command -v "$command_name" >/dev/null 2>&1; then
        record_failure "build/live command is visible inside the static sandbox: $command_name"
      fi
    done
    if ((failures != initial_failures)); then
      return 1
    fi
  fi

  run_gate "Python guard unit tests" run_python_guard_tests || true
  run_gate "new shell syntax" check_new_shell_syntax || true
  run_gate "new shell lint" \
    shellcheck "$script_dir/guards.sh" "$script_dir/ci_local.sh" \
      "$script_dir/check-authorship.sh" || true
  run_gate "absorbed interoperability guards" "$script_dir/guards.sh" || true

  run_gate "workspace boundaries" "$script_dir/check-boundaries.sh" || true
  run_gate "two-nonce adaptor boundary" "$script_dir/check-adaptor-two-nonce.sh" || true
  run_gate "claim adaptor provenance" "$script_dir/check-claim-adaptor-provenance.sh" || true
  run_gate "hash-domain freeze" "$script_dir/check-hash-domains.sh" || true
  run_gate "normative adjudication" "$script_dir/check-normative-adjudication.sh" || true
  run_gate "policy topology" "$script_dir/check-policy-topology.sh" || true
  run_gate "shared-output Bulletproof boundary" "$script_dir/check-shared-output-bp.sh" || true
  run_gate "ratification signatures" "$script_dir/check-ratification-signatures.sh" || true
  run_gate "mainnetswap publication boundary" check_publication_boundary || true

  run_gate "absorption manifest" python3 -B "$script_dir/check-absorption-manifest.py" || true
  run_gate "production-readiness manifest" \
    python3 -B "$script_dir/check-production-readiness-manifest.py" || true

  ((failures == initial_failures))
}

run_offline() {
  run_static || return 1

  local initial_failures="$failures"
  require_command cargo || return 1
  require_command rustfmt || return 1
  require_command sha256sum || return 1
  if [[ "$(uname -s)" != "Linux" ]]; then
    record_failure "the operational layer Cargo gate is Linux-only"
    return 1
  fi

  export CARGO_NET_OFFLINE=true
  export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
  local lock_digest_before
  lock_digest_before="$(sha256sum "$repo/Cargo.lock")" || {
    record_failure "could not hash Cargo.lock before offline gates"
    return 1
  }

  local package_output
  if ! package_output="$(python3 -B "$script_dir/guard_layer_policy.py" \
      --root "$repo" --print-layer-packages)"; then
    record_failure "could not derive the fail-closed layer package set"
    return 1
  fi

  local -a packages=()
  local -a package_args=()
  mapfile -t packages <<<"$package_output"
  local package
  for package in "${packages[@]}"; do
    if [[ ! "$package" =~ ^[A-Za-z0-9_-]+$ ]]; then
      record_failure "invalid package name returned by policy scanner"
      return 1
    fi
    package_args+=("--package=$package")
  done
  if ((${#package_args[@]} == 0)); then
    record_failure "policy scanner returned an empty layer package set"
    return 1
  fi

  run_gate "locked offline metadata" \
    cargo metadata --locked --offline --format-version 1 --no-deps || return 1
  run_gate "workspace formatting" cargo fmt --all -- --check || true
  run_gate "layer check" \
    cargo check --locked --offline "${package_args[@]}" --all-targets || true
  run_gate "layer clippy" \
    cargo clippy --locked --offline "${package_args[@]}" --all-targets -- -D warnings || true
  run_gate "layer tests" \
    cargo test --locked --offline "${package_args[@]}" --all-targets || true
  run_gate "layer documentation tests" \
    cargo test --locked --offline "${package_args[@]}" --doc || true

  run_gate "real DOM adaptor backend" \
    cargo test --locked --offline --package dom-leg \
      --features real-dom-adaptor --all-targets || true
  run_gate "real EVM HTTP backend" \
    cargo test --locked --offline --package adapter-evm \
      --features rpc-http --all-targets || true
  run_gate "production daemon check" \
    cargo check --locked --offline --package dom-interopd \
      --no-default-features --features production --lib --bins || true
  run_gate "production daemon clippy" \
    cargo clippy --locked --offline --package dom-interopd \
      --no-default-features --features production --lib --bins -- -D warnings || true
  run_gate "production daemon tests" \
    cargo test --locked --offline --package dom-interopd \
      --no-default-features --features production --lib --bins || true
  run_gate "Store release-surface refusal" "$script_dir/check-release-surface.sh" || true
  run_gate "Relay release-surface refusal" "$script_dir/check-relay-fault-surface.sh" || true

  local lock_digest_after
  lock_digest_after="$(sha256sum "$repo/Cargo.lock")" || {
    record_failure "could not hash Cargo.lock after offline gates"
    return 1
  }
  if [[ "$lock_digest_after" != "$lock_digest_before" ]]; then
    record_failure "Cargo.lock changed during locked offline gates"
  fi

  ((failures == initial_failures))
}

run_live_local() {
  run_offline || return 1

  local initial_failures="$failures"
  local command_name
  for command_name in bitcoin-cli bitcoind forge anvil cast; do
    require_command "$command_name" || true
  done
  if ((failures != initial_failures)); then
    return 1
  fi

  local foundry_dir
  foundry_dir="$(dirname -- "$(command -v forge)")"
  export FOUNDRY_BIN="${FOUNDRY_BIN:-$foundry_dir}"
  export FORGE_BIN="${FORGE_BIN:-$FOUNDRY_BIN/forge}"

  run_gate "EVM contract release" "$repo/contracts/scripts/check_release.sh" || true
  run_gate "local Anvil E2E" "$script_dir/e2e_anvil.sh" || true
  run_gate "local Bitcoin Core Regtest E2E" "$script_dir/f5-regtest-e2e.sh" || true

  ((failures == initial_failures))
}

network_namespace_is_loopback_only() {
  local interface_count=0
  local interface_name remainder
  while IFS=: read -r interface_name remainder; do
    [[ -z "$remainder" ]] && continue
    interface_name="${interface_name//[[:space:]]/}"
    [[ -z "$interface_name" ]] && continue
    if [[ "$interface_name" != "lo" ]]; then
      return 1
    fi
    interface_count=$((interface_count + 1))
  done </proc/net/dev
  ((interface_count == 1))
}

enter_mode_sandbox() {
  case "$mode" in
    --static)
      if [[ "${DOM_CI_STATIC_SANDBOX:-0}" == "1" ]]; then
        local current_namespace=""
        current_namespace="$(readlink /proc/self/ns/net 2>/dev/null || true)"
        if [[ ! "${DOM_CI_PARENT_NETNS:-}" =~ ^net:\[[0-9]+\]$ \
              || "$current_namespace" == "$DOM_CI_PARENT_NETNS" ]]; then
          record_failure "the static network namespace was not isolated"
          return 1
        fi
        if ! network_namespace_is_loopback_only; then
          record_failure "the static network namespace exposes a non-loopback interface"
          return 1
        fi
        local mount_options
        mount_options="$(findmnt -T "$repo" -n -o OPTIONS 2>/dev/null || true)"
        if [[ ",$mount_options," != *,ro,* ]]; then
          record_failure "the static sandbox did not mount the repository read-only"
          return 1
        fi
        return 0
      fi
      require_command bwrap || return 1
      require_command findmnt || return 1
      local parent_namespace=""
      parent_namespace="$(readlink /proc/self/ns/net 2>/dev/null || true)"
      if [[ ! "$parent_namespace" =~ ^net:\[[0-9]+\]$ ]]; then
        record_failure "could not identify the parent network namespace"
        return 1
      fi
      exec bwrap --die-with-parent --ro-bind / / --dev /dev --proc /proc \
        --tmpfs /tmp --unshare-net --chdir "$repo" \
        --setenv DOM_CI_STATIC_SANDBOX 1 \
        --setenv DOM_CI_PARENT_NETNS "$parent_namespace" \
        --setenv PATH /usr/bin:/bin \
        "$script_dir/ci_local.sh" "$mode"
      ;;
    --offline|--live-local)
      if [[ "${DOM_CI_NETWORK_SANDBOX:-0}" == "1" ]]; then
        local current_namespace=""
        current_namespace="$(readlink /proc/self/ns/net 2>/dev/null || true)"
        if [[ ! "${DOM_CI_PARENT_NETNS:-}" =~ ^net:\[[0-9]+\]$ \
              || "$current_namespace" == "$DOM_CI_PARENT_NETNS" ]]; then
          record_failure "the offline/live-local network namespace was not isolated"
          return 1
        fi
        if ! network_namespace_is_loopback_only; then
          record_failure "the offline/live-local namespace exposes a non-loopback interface"
          return 1
        fi
        if ! ip link set lo up; then
          record_failure "could not enable isolated loopback"
          return 1
        fi
        return 0
      fi
      require_command unshare || return 1
      require_command ip || return 1
      local parent_namespace=""
      parent_namespace="$(readlink /proc/self/ns/net 2>/dev/null || true)"
      if [[ ! "$parent_namespace" =~ ^net:\[[0-9]+\]$ ]]; then
        record_failure "could not identify the parent network namespace"
        return 1
      fi
      exec unshare --user --map-root-user --net -- \
        env DOM_CI_NETWORK_SANDBOX=1 DOM_CI_PARENT_NETNS="$parent_namespace" \
        "$script_dir/ci_local.sh" "$mode"
      ;;
    *)
      return 0
      ;;
  esac
}

if (($# > 1)); then
  usage >&2
  exit 2
fi

if ! enter_mode_sandbox; then
  printf '\nLOCAL_CI = FAIL (%d gate(s))\n' "$failures" >&2
  exit 1
fi

case "$mode" in
  --static)
    run_static || true
    ;;
  --offline)
    run_offline || true
    ;;
  --live-local)
    run_live_local || true
    ;;
  --help|-h)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

if ((failures != 0)); then
  printf '\nLOCAL_CI = FAIL (%d gate(s))\n' "$failures" >&2
  exit 1
fi
printf '\nLOCAL_CI = PASS (%s)\n' "${mode#--}"
