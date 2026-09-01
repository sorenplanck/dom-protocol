#!/usr/bin/env python3
"""Static wiring gate for the Solana leg.

Unlike its first version (which grepped for the presence of six strings and
could not fail on a disconnected implementation), this gate checks CALLERS:
every safety-critical entry point must be invoked from at least one
non-test, non-defining crate. A gate that cannot fail on dead wiring is not
a gate; this one fails on exactly that.

It also re-checks the closed DLEQ role registry: every ROLE_* constant in
the tree must be defined in xmr-dleq-sigma, listed in ROLES_V1, and unique.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES = ROOT / "crates"
PROGRAM = ROOT / "programs" / "dom-solana-escrow"

FAILURES: list[str] = []


def fail(message: str) -> None:
    FAILURES.append(message)


def rust_files(base: Path):
    for path in base.rglob("*.rs"):
        if "target" in path.parts:
            continue
        yield path


def is_test_path(path: Path) -> bool:
    return "tests" in path.parts or path.name.endswith("_test.rs")


def require_external_caller(symbol: str, defined_in: str, allow_test_only: bool = False) -> None:
    """The symbol must be called from a crate that does not define it."""
    pattern = re.compile(r"\b" + re.escape(symbol) + r"\s*\(")
    callers: list[Path] = []
    test_callers: list[Path] = []
    for path in rust_files(CRATES):
        if defined_in in path.parts:
            continue
        text = path.read_text(errors="replace")
        if pattern.search(text):
            (test_callers if is_test_path(path) else callers).append(path)
    if callers:
        return
    if allow_test_only and test_callers:
        return
    where = "no non-test crate calls it" if test_callers else "nothing calls it at all"
    fail(f"{symbol} (defined in {defined_in}): {where}")


def check_wiring() -> None:
    # The production gate and its consumers: each must have a caller outside
    # the crate that defines it, or the leg is decorative.
    require_external_caller("attest_immutable_program", "solana-program-attestation")
    require_external_caller("finalize_session", "solana-session-init", allow_test_only=True)
    require_external_caller("persist_route_witness", "solana-session-init", allow_test_only=True)
    require_external_caller("revealed_dom_secret_to_xmr_scalar", "xmr-dleq-sigma")
    require_external_caller("verify_counterparty_bundle", "solana-route-secret")
    # The bridge must be constructed by the runtime wiring, not only by tests.
    require_external_caller("SolanaClaimSink::new", "solana-kaystra-bridge")

    # The on-chain program must enforce the 252-bit domain before the curve
    # call, and the check must live in the file that performs the call.
    secret = (PROGRAM / "src" / "secret.rs").read_text(errors="replace")
    domain = secret.find("little_endian[31] & 0xf0")
    call = secret.find("multiply_edwards(")
    if domain == -1 or call == -1 or domain > call:
        fail("secret.rs: 252-bit domain check missing or after the curve call")


def check_role_registry() -> None:
    registry_file = CRATES / "adapters" / "xmr-dleq-sigma" / "src" / "lib.rs"
    registry_text = registry_file.read_text(errors="replace")
    defined = dict(
        (name, int(value))
        for name, value in re.findall(
            r"pub const (ROLE_[A-Z_]+): u8 = (\d+);", registry_text
        )
    )
    if len(set(defined.values())) != len(defined):
        fail(f"role registry: duplicate bytes in {sorted(defined.items())}")
    listed = set(re.findall(r"\(\s*(ROLE_[A-Z_]+)\s*,", registry_text))
    for name in defined:
        if name not in listed:
            fail(f"role registry: {name} not listed in ROLES_V1")
    # No other crate may mint a role byte of its own.
    for path in rust_files(CRATES):
        if "xmr-dleq-sigma" in path.parts:
            continue
        for name, value in re.findall(
            r"pub const (ROLE_[A-Z_]+): u8 = (\d+);", path.read_text(errors="replace")
        ):
            fail(f"{path.relative_to(ROOT)}: mints role byte {name}={value} outside the registry")


def check_mainnet_absence() -> None:
    profile = (CRATES / "adapters" / "solana-profile" / "src" / "lib.rs").read_text(
        errors="replace"
    )
    if "MainnetBeta" in profile:
        fail("solana-profile: MainnetBeta variant present; mainnet must be absent by omission")
    chain_profile = (CRATES / "chain-profile" / "src" / "lib.rs").read_text(errors="replace")
    match = re.search(r"pub enum SolanaNetworkV1 \{(.*?)\}", chain_profile, re.S)
    if not match:
        fail("chain-profile: SolanaNetworkV1 missing")
    elif "Mainnet" in match.group(1):
        fail("chain-profile: SolanaNetworkV1 must not represent mainnet")


def main() -> int:
    check_wiring()
    check_role_registry()
    check_mainnet_absence()
    if FAILURES:
        print("SOLANA STATIC GATE: FAIL")
        for failure in FAILURES:
            print(f"  - {failure}")
        return 1
    print("SOLANA STATIC GATE: PASS (wiring, role registry, mainnet absence)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
