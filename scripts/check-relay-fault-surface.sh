#!/usr/bin/env bash
# Verify the release boundary of the Relay fault-injection surface.
#
# A SIBLING of check-release-surface.sh, not an extension of it. That script
# pins one exact diagnostic on its line 8 and answers for the Store; these are
# independent subjects, and separate guards give attributable failures.
#
# POLICY EXTENSION, decided by the operator: the rule the Store already carries
# is extended to the Relay. It is a safeguard against a build-configuration
# mistake in a component third parties compile, not a security fix.
set -Eeuo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

diagnostic="the relay fault-injection surface is forbidden in release builds"
log="$(mktemp -t dom-relay-fault-surface-XXXXXX)"
trap 'rm -f "$log"' EXIT

# The supported Relay surface must remain compilable with release assertions.
cargo check --release --locked -p relay

# The laboratory surface must be impossible to include in that same profile.
# Treat a different compiler failure as a failed gate, so dependency or
# toolchain breakage cannot masquerade as the intended policy rejection.
if cargo check --release --locked -p relay \
    --features relay-fault-injection >"$log" 2>&1; then
  echo "release build unexpectedly accepted the Relay fault-injection surface" >&2
  exit 1
fi

if ! grep -Fq "$diagnostic" "$log"; then
  echo "release build failed without the required fault-injection diagnostic" >&2
  tail -40 "$log" >&2
  exit 1
fi

# The barrier must also SURVIVE in debug: this bars an accident, it does not
# amputate the crate. A guard that quietly removed the laboratory capability
# would be a worse defect than the one it prevents.
cargo check --locked -p relay --features relay-fault-injection

echo "RELAY_FAULT_SURFACE = PASS"
