#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

now_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

extract_tests() {
  local path
  local files=()
  for path in "$@"; do
    [[ -e "$path" ]] || continue
    if [[ -d "$path" ]]; then
      while IFS= read -r file; do
        files+=("$file")
      done < <(find "$path" -type f -name '*.rs' | sort)
    else
      files+=("$path")
    fi
  done
  ((${#files[@]} > 0)) || return 0
  awk '
    BEGIN {
      has_test = 0
      ignore = ""
    }
    FNR == 1 {
      has_test = 0
      ignore = ""
    }
    /^[[:space:]]*#\[(tokio::)?test([[:space:]]*\(.*\))?\]/ {
      has_test = 1
      next
    }
    /^[[:space:]]*#\[ignore/ {
      if (match($0, /#\[ignore[[:space:]]*=[[:space:]]*"[^"]+"/)) {
        ignore = substr($0, RSTART, RLENGTH)
        sub(/^#\[ignore[[:space:]]*=[[:space:]]*"/, "", ignore)
        sub(/"\]$/, "", ignore)
        sub(/"$/, "", ignore)
      } else {
        ignore = "ignored without reason"
      }
      next
    }
    has_test && /^[[:space:]]*(async[[:space:]]+)?fn[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\(/ {
      line = $0
      sub(/^[[:space:]]*(async[[:space:]]+)?fn[[:space:]]+/, "", line)
      sub(/[[:space:]]*\(.*/, "", line)
      status = (ignore == "") ? "active" : "ignored: " ignore
      printf "- `%s::%s` (%s)\n", FILENAME, line, status
      has_test = 0
      ignore = ""
    }
  ' "${files[@]}"
}

ignored_tests() {
  local files=()
  while IFS= read -r file; do
    files+=("$file")
  done < <(find crates -type f -name '*.rs' | sort)
  ((${#files[@]} > 0)) || return 0
  awk '
    BEGIN { ignore = "" }
    FNR == 1 { ignore = "" }
    /^[[:space:]]*#\[ignore/ {
      if (match($0, /#\[ignore[[:space:]]*=[[:space:]]*"[^"]+"/)) {
        ignore = substr($0, RSTART, RLENGTH)
        sub(/^#\[ignore[[:space:]]*=[[:space:]]*"/, "", ignore)
        sub(/"\]$/, "", ignore)
        sub(/"$/, "", ignore)
      } else {
        ignore = "ignored without reason"
      }
      next
    }
    ignore != "" && /^[[:space:]]*(async[[:space:]]+)?fn[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\(/ {
      line = $0
      sub(/^[[:space:]]*(async[[:space:]]+)?fn[[:space:]]+/, "", line)
      sub(/[[:space:]]*\(.*/, "", line)
      printf "- `%s::%s` — %s\n", FILENAME, line, ignore
      ignore = ""
    }
  ' "${files[@]}"
}

domain() {
  local title="$1"
  shift
  printf '\n## %s\n\n' "$title"
  extract_tests "$@"
}

cat <<EOF
# Critical Domain Coverage Report

Generated: ${now_utc}

This report groups tests by critical invariant domain. It is not a line
coverage report and does not claim that line coverage is proof coverage. The
goal is to expose which invariant families have executable tests, which tests
are environment-gated, and where important proof gaps remain.
EOF

domain "consensus" \
  crates/dom-consensus/src \
  crates/dom-consensus/tests \
  crates/dom-chain/tests/aggregate_balance_adversarial.rs \
  crates/dom-chain/tests/block_validation_ingress_adversarial.rs \
  crates/dom-pow/tests

domain "persistence" \
  crates/dom-store/tests \
  crates/dom-chain/tests/corruption_detection.rs \
  crates/dom-integration-tests/tests/chain_persistence.rs

domain "replay" \
  crates/dom-integration-tests/tests/replay_determinism.rs \
  crates/dom-node/tests/multinode_reordered_delivery.rs \
  crates/dom-node/src/replay_snapshot.rs

domain "convergence" \
  crates/dom-node/tests/multinode_reordered_delivery.rs \
  crates/dom-node/src/orphan_pool.rs \
  crates/dom-node/src/future_block_queue.rs \
  crates/dom-integration-tests/tests/ibd.rs \
  crates/dom-integration-tests/tests/reorg.rs \
  crates/dom-integration-tests/tests/late_join.rs \
  crates/dom-integration-tests/tests/two_node.rs \
  crates/dom-integration-tests/tests/three_node.rs

domain "runtime" \
  crates/dom-node/src/task_supervisor.rs \
  crates/dom-node/src/node.rs \
  crates/dom-node/src/future_block_queue.rs \
  crates/dom-integration-tests/src/helpers.rs \
  crates/dom-integration-tests/tests/chain_persistence.rs

domain "P2P" \
  crates/dom-wire/src \
  crates/dom-wire/tests \
  crates/dom-integration-tests/tests/adversarial_handshake.rs \
  crates/dom-integration-tests/tests/adversarial_outbound.rs \
  crates/dom-integration-tests/tests/adversarial_relay.rs \
  crates/dom-integration-tests/tests/mempool_relay.rs \
  crates/dom-integration-tests/tests/two_node.rs \
  crates/dom-integration-tests/tests/three_node.rs \
  crates/dom-integration-tests/tests/late_join.rs

domain "mempool" \
  crates/dom-mempool/src \
  crates/dom-mempool/tests \
  crates/dom-node/src/relay \
  crates/dom-integration-tests/tests/mempool_relay.rs

domain "wallet" \
  crates/dom-wallet/src \
  crates/dom-wallet/tests \
  crates/dom-integration-tests/tests/wallet_flow.rs \
  crates/dom-integration-tests/tests/spend_e2e.rs

cat <<'EOF'

## ignored / environment-gated tests

EOF
ignored_tests

cat <<'EOF'

## known invariant coverage gaps

- Consensus: independent implementation reproduction is still required for
  frozen RandomX and Bulletproof-related vectors before mainnet launch.
- Consensus: the CI gate exercises the in-tree validator heavily, but it is
  not a formal proof that all economic-balance and serialization invariants
  are complete across independent implementations.
- Persistence: crash/reopen tests cover LMDB and canonical rebuild paths, but
  do not exhaustively model every possible torn write point across every host
  filesystem.
- Replay: deterministic replay timelines cover selected reorder, duplicate,
  reconnect, and restart schedules; they do not enumerate all network
  interleavings.
- Convergence: multi-node IBD/reorg tests run under Regtest fast mining in CI;
  full RandomX wall-clock behavior remains an environment/performance concern,
  not a separate invariant proof.
- Runtime: shutdown tests cover supervisor cancellation and restartability, but
  not every possible cancellation point in every async task.
- P2P: adversarial handshake/relay/outbound tests cover bounded cleanup and
  malformed traffic cases, but do not replace fuzzing of every wire payload.
- Mempool: ordering, conflict, reinjection, and relay tests cover core
  invariants, but policy economics under sustained live peer pressure remain a
  broader simulation gap.
- Wallet: lifecycle, rollback, canonical rescan, and spend-flow tests cover
  key user-state invariants, but hardware/OS-specific wallet storage failure
  modes are not exhaustively covered.
EOF
