#!/usr/bin/env bash
# The DOM gates, scoped to the nineteen crates this package installs. Run from
# anywhere inside the target checkout. No output is piped through head or tail:
# a pipeline would discard the exit code that decides whether the gate passed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# xmr-claim-registry is in this list. It was missing from the V6 gate script
# while being installed as a workspace member, so it was never linted or tested.
SCOPE="-p xmr-crypto -p xmr-dleq-sigma -p xmr-route-secret -p xmr-profile \
-p xmr-claim-registry -p xmr-evidence -p xmr-observer -p xmr-kaystra-records \
-p xmr-secret-store -p xmr-sidecar-auth -p xmr-live-sidecar-api \
-p xmr-live-sidecar-uds-client -p xmr-raw-tx-verify -p xmr-spend-port \
-p xmr-delivery -p xmr-delivery-sqlite -p xmr-settlement-observer \
-p xmr-kaystra-bridge -p f8-xmr-kaystra-e2e"

python3 scripts/xmr-v6/static-validate.py "$ROOT"
cargo fmt --all -- --check
cargo check $SCOPE --all-targets
cargo clippy $SCOPE --all-targets -- -D warnings
cargo test $SCOPE --all-targets

echo
echo "MIT gates passed."
echo "The GPL sidecar is a separate binary and a separate licence boundary."
echo "Build it deliberately, not as part of this gate:"
echo "    bash scripts/xmr-v6/build-sidecar.sh"
