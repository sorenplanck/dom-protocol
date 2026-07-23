#!/usr/bin/env bash
# Generate (never hand-write) the unsigned sidecar release manifest from the
# exact dom-node executable that will be published. Minisign the resulting JSON
# in the release pipeline after review.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <mainnet|testnet|regtest> <artifact-url>" >&2
  exit 2
fi

: "${DOM_SIDECAR_ARTIFACT_PLATFORM:?set platform, e.g. linux-x86_64}"
: "${DOM_MIN_WALLET_VERSION:?set minimum wallet version}"
: "${DOM_SIDECAR_PUBLISHED_AT:?set RFC3339 publication timestamp}"

DOM_SIDECAR_ARTIFACT_URL="$2" \
  target/release/dom-node --sidecar-manifest "$1" > sidecar-manifest.json

echo "generated sidecar-manifest.json from target/release/dom-node; sign it with minisign before publishing" >&2
