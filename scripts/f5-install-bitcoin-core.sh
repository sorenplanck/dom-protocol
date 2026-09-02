#!/usr/bin/env bash
# F5 — pinned Bitcoin Core installer for the regtest harness.
#
# RECONSTRUCTION (2026-09-02): this artifact never existed in this repository;
# it is rebuilt from the roadmap requirement against the version the regtest
# harness actually runs. Signet was cancelled; regtest is the only Bitcoin
# execution environment this installs for.
#
# Fail-closed by construction:
#   * one pinned version and one pinned SHA256 — a drifted tarball is deleted
#     and the install refuses; no "latest", no fallback mirror;
#   * the checksum is verified before anything is unpacked;
#   * installs only into a user-owned prefix (no sudo, no system paths);
#   * refuses to overwrite a different existing version unless FORCE=1.
set -euo pipefail

VERSION="31.0"
TARBALL="bitcoin-${VERSION}-x86_64-linux-gnu.tar.gz"
SHA256="d3e4c58a35b1d0a97a457462c94f55501ad167c660c245cb1ffa565641c65074"
BASE_URL="https://bitcoincore.org/bin/bitcoin-core-${VERSION}"
PREFIX="${BITCOIN_PREFIX:-$HOME/.local}"
FORCE="${FORCE:-0}"

if [ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]; then
  echo "this installer pins Linux x86_64 only" >&2
  exit 1
fi

if command -v "$PREFIX/bin/bitcoind" >/dev/null 2>&1; then
  installed="$("$PREFIX/bin/bitcoind" --version | head -1)"
  case "$installed" in
    *"v${VERSION}"*)
      echo "bitcoind v${VERSION} already installed at $PREFIX/bin — nothing to do"
      exit 0
      ;;
    *)
      if [ "$FORCE" != "1" ]; then
        echo "a different bitcoind is installed ($installed); rerun with FORCE=1 to replace" >&2
        exit 1
      fi
      ;;
  esac
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "== downloading ${TARBALL} =="
curl -fsSLo "$TARBALL" "$BASE_URL/$TARBALL"

echo "== verifying pinned SHA256 =="
echo "${SHA256}  ${TARBALL}" | sha256sum -c - || {
  echo "checksum mismatch: refusing to install a drifted tarball" >&2
  exit 1
}

echo "== unpacking and installing to $PREFIX =="
tar -xzf "$TARBALL"
mkdir -p "$PREFIX/bin"
install -m 0755 "bitcoin-${VERSION}/bin/bitcoind" "$PREFIX/bin/bitcoind"
install -m 0755 "bitcoin-${VERSION}/bin/bitcoin-cli" "$PREFIX/bin/bitcoin-cli"

"$PREFIX/bin/bitcoind" --version | head -1
echo "installed. Ensure $PREFIX/bin is on PATH before running f5-regtest-e2e.sh"
