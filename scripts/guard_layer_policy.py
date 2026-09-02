#!/usr/bin/env python3
"""Fail-closed static policy checks for the DOM interoperability layer.

The original interop guard was a useful checklist, but it searched comments,
doctests and test-only Rust as if they were production code.  This module keeps
the useful policies while making their scope explicit.  It deliberately uses
only the Python standard library so the static gate does not resolve or build
Rust dependencies.
"""

from __future__ import annotations

import argparse
import ast
import collections
import dataclasses
import hashlib
import json
import pathlib
import re
import sys
import tomllib
from collections.abc import Iterable, Sequence


ROOT = pathlib.Path(__file__).resolve().parents[1]

# These are the immutable node members and the explicitly non-product
# acceptance harnesses in the merged workspace.  Every other workspace member
# is scanned as production interoperability code.  A newly added member is
# therefore covered by default instead of silently falling outside the gate.
NODE_MEMBERS = frozenset(
    {
        "crates/dom-agent-runner",
        "crates/dom-chain",
        "crates/dom-cli",
        "crates/dom-config",
        "crates/dom-consensus",
        "crates/dom-core",
        "crates/dom-crypto",
        "crates/dom-explorer",
        "crates/dom-faucet",
        "crates/dom-integration-tests",
        "crates/dom-mempool",
        "crates/dom-node",
        "crates/dom-pmmr",
        "crates/dom-pow",
        "crates/dom-rpc",
        "crates/dom-serialization",
        "crates/dom-slate",
        "crates/dom-store",
        "crates/dom-test-runner",
        "crates/dom-test-vectors",
        "crates/dom-tx",
        "crates/dom-wallet",
        "crates/dom-wallet-app",
        "crates/dom-wallet-core-api",
        "crates/dom-wallet-crypto",
        "crates/dom-wallet-keys",
        "crates/dom-wallet-recovery",
        "crates/dom-wallet2",
        "crates/dom-wire",
    }
)

HARNESS_MEMBERS = frozenset(
    {
        "crates/adapters/btc-evidence",
        "crates/adapters/btc-live",
        "crates/adapters/btc-observer",
        "crates/adapters/btc-secp-c1a",
        "crates/adapters/dom-sim",
        "crates/f2-harness",
        "crates/f2-model",
        "crates/f3-harness",
        "crates/f4-harness",
        "crates/f4-model",
        "crates/f5-e2e",
        "crates/f6-model",
        "crates/f7-e2e",
    }
)

# Existing production exceptions are frozen by path, exact source line and
# multiplicity.  This is intentionally stricter than recognizing an inline
# marker: adding, moving between files, duplicating or rewriting an exception
# requires an explicit review here.
I14_ALLOWLIST: collections.Counter[tuple[str, str]] = collections.Counter(
    {
        (
            "crates/adapters/btc/src/codec.rs",
            'let mut h = Blake2bVar::new(32).expect("BLAKE2b-256 output size is valid"); // I14-ALLOW: fixed 32-byte output is always valid',
        ): 1,
        (
            "crates/adapters/btc/src/codec.rs",
            '.expect("BLAKE2b-256 output size is valid"); // I14-ALLOW: fixed 32-byte output',
        ): 1,
        (
            "crates/dom-adaptor/src/bulletproof_mpc.rs",
            '.expect("validated BP statement always contains a 32-byte chain ID")',
        ): 1,
        (
            "crates/dom-adaptor/src/bulletproof_mpc.rs",
            '.expect("validated BP statement always contains a 32-byte session ID")',
        ): 1,
        (
            "crates/dom-interopd/src/production_config.rs",
            'writeln!(&mut body, "{HEADER_V1}").expect("string write cannot fail");',
        ): 1,
        (
            "crates/dom-interopd/src/production_config.rs",
            'writeln!(&mut body, "mode={}", self.mode.as_str()).expect("string write cannot fail");',
        ): 1,
        (
            "crates/dom-interopd/src/production_config.rs",
            '.expect("string write cannot fail");',
        ): 1,
        (
            "crates/dom-interopd/src/production_config.rs",
            'writeln!(target, "{key}={}", encode_hex(&value)).expect("string write cannot fail");',
        ): 1,
        (
            "crates/dom-scriptless-bulletproof/src/sec1_zkp_bridge.rs",
            '.expect("Y from a valid curve point is a valid field element");',
        ): 1,
        (
            "crates/dom-scriptless-bulletproof/src/sec1_zkp_bridge.rs",
            "let x_bytes: [u8; 32] = zkp_bytes[1..].try_into().unwrap();",
        ): 1,
        (
            "crates/dom-scriptless-bulletproof/src/sec1_zkp_bridge.rs",
            "let y: [u8; 32] = uncompressed[33..65].try_into().unwrap();",
        ): 1,
        (
            "crates/dom-scriptless-bulletproof/src/sec1_zkp_bridge.rs",
            "let y_bytes: [u8; 32] = uncompressed[33..65].try_into().unwrap();",
        ): 1,
        (
            "crates/dom-scriptless-primitives/src/curve.rs",
            "Ok(ProjectivePoint::from(ct.unwrap()))",
        ): 1,
        (
            "crates/dom-scriptless-primitives/src/curve.rs",
            "Some(ct.unwrap())",
        ): 1,
        (
            "crates/kaystra-core/src/store_port.rs",
            'let mut h = blake2::Blake2bVar::new(32).expect("blake2 output size"); // I14-ALLOW: fixed-size BLAKE2 output',
        ): 1,
        (
            "crates/kaystra-core/src/store_port.rs",
            'h.finalize_variable(&mut out).expect("blake2 finalize"); // I14-ALLOW: fixed-size BLAKE2 output',
        ): 1,
        (
            "crates/route-transport/src/durable_sender.rs",
            '.expect("framed DSC1 bound fits u32"),',
        ): 1,
    }
)

I6_ALLOWLIST: collections.Counter[tuple[str, str]] = collections.Counter(
    {
        (
            "crates/deployment-registry/examples/verify_evm_contract_release.rs",
            "println!(",
        ): 1,
        ("crates/dom-interopd/src/main.rs", 'println!("{json}");'): 2,
        # The reviewed inventory rose on 2026-08-30 when the `run` arm was written.  The
        # reviewed question is the one this list exists to ask: is this the
        # process entry point writing to stderr on a terminal branch that then
        # returns a failing `ExitCode`, or is it output escaping from library
        # code?  All three are the former, in `main.rs`, and two of them are
        # error line is byte-identical to one already inventoried here, while
        # the production usage banner is frozen by its exact constant-bearing
        # line.  The remaining entry enumerates `MISSING_PRODUCTION_PARTS_V1`, which is
        # the refusal behaviour itself: a composition root that will not start
        # has to say which parts are absent, or the operator is left to guess.
        # Reviewed 2026-09-02 (Stage 13 guard pass).  The stage-7 and stage-10
        # composition roots changed two things in `main.rs`, and the inventory
        # says which.  The fourth `eprintln!("{error}")` is `run` refusing a
        # non-operational artifact (`require_operational_artifact_v1`) on a
        # terminal branch that returns `ExitCode::FAILURE`.  The
        # `MISSING_PRODUCTION_PARTS_V1` enumeration became the
        # `PRODUCTION_KNOWN_LIMITS_V1` enumeration once the daemon could drive
        # a route: same shape, the operator is told which paths refuse by
        # policy before the route starts.  Both are the entry point writing to
        # stderr, not output escaping from library code.
        ("crates/dom-interopd/src/main.rs", 'eprintln!("{error}");'): 4,
        ("crates/dom-interopd/src/main.rs", "eprintln!("): 1,
        (
            "crates/dom-interopd/src/main.rs",
            'eprintln!("{PRODUCTION_USAGE_V1}");',
        ): 1,
        ("crates/dom-interopd/src/main.rs", 'eprintln!("  known limit: {limit}");'): 1,
        (
            "crates/dom-interopd/src/main.rs",
            'eprintln!("usage: dom-interopd self-check [--json]");',
        ): 1,
        (
            "crates/dom-interopd/src/main.rs",
            'eprintln!("simulation report encoding failed");',
        ): 1,
    }
)

F1_SPONSOR_ALLOWLIST: collections.Counter[tuple[str, str]] = collections.Counter(
    {
        (
            "crates/dom-actuator/src/contracts.rs",
            "PurposeV1::Sponsor => Err(DomActuatorError::CapabilityMismatch),",
        ): 1,
        (
            "crates/dom-adaptor/src/context.rs",
            "(PurposeV1::Sponsor, _) => {",
        ): 1,
        (
            "crates/dom-adaptor/src/context.rs",
            "PurposeV1::Sponsor.to_byte(),",
        ): 1,
        (
            "crates/dom-adaptor/src/nonce.rs",
            "PurposeV1::ClaimAdaptor | PurposeV1::RefundAdaptor | PurposeV1::Sponsor => {",
        ): 1,
        (
            "crates/dom-adaptor/src/transcript.rs",
            "(PurposeV1::Sponsor, _) => Err(AdaptorError::PurposeNotAuthorized(",
        ): 1,
        (
            "crates/dom-adaptor/src/transcript.rs",
            "PurposeV1::Sponsor.to_byte(),",
        ): 1,
        # Reviewed 2026-09-02.  `RefundAdaptor = 0x05` (NAR-DC-P1-009) joined
        # the purpose registry and rustfmt split both exhaustive arms across
        # lines, so the one two-count entry became two one-count entries.
        # Sponsor still only round-trips its byte here; nothing signs.
        (
            "crates/dom-scriptless-crypto/src/storage.rs",
            "| PurposeV1::Sponsor => Ok(purpose),",
        ): 1,
        (
            "crates/dom-scriptless-crypto/src/storage.rs",
            "| PurposeV1::Sponsor => purpose.to_byte(),",
        ): 1,
        # Reviewed 2026-09-02.  The restored Wallet V3 compositor (evidence
        # cut, `f7-wallet-compositor-evidence-only`) names Sponsor three times
        # and every arm fails closed: two `Binding` errors where a purpose
        # selects a DSC1 checkpoint kind or a nonce vault, and `FailedClosed`
        # in `economic_phase_for_purpose`.  It composes no sponsor round.
        (
            "crates/dom-leg/src/f7_wallet.rs",
            "PurposeV1::Sponsor | PurposeV1::RefundAdaptor => {",
        ): 2,
        (
            "crates/dom-leg/src/f7_wallet.rs",
            "PurposeV1::Sponsor | PurposeV1::RefundAdaptor => SessionPhaseV1::FailedClosed,",
        ): 1,
        (
            "crates/dom-scriptless-store/src/runtime/linux/session_store.rs",
            "PurposeV1::Sponsor => return [0; 32],",
        ): 1,
        (
            "crates/dom-scriptless-store/src/runtime/linux/session_store.rs",
            "PurposeV1::Sponsor => SessionPhaseV1::FailedClosed,",
        ): 2,
        (
            "crates/dom-scriptless-store/src/runtime/linux/session_store.rs",
            "PurposeV1::Sponsor => Err(SessionStoreError::InvalidTransition),",
        ): 1,
        # Reviewed 2026-08-30.  Unlike the four entries above it, this one is
        # NOT a live production decision, and the inventory should say so
        # rather than let the guard's "production use" label imply a human
        # certified a reachable Sponsor path.  What the reviewer actually saw:
        # the arm sits in `PreparedSigningPayloads::new`, a test-fixture
        # builder inside `mod evidence_only_staging`, which is gated
        # `#[cfg(any(test, feature = "evidence-only"))]` -- and lib.rs
        # `compile_error!`s if that feature is on in a release build.  Inside
        # a debug build it is still unreachable: the function's own entry gate
        # already returns for both `(Sponsor, Some(_))` and `(Sponsor, None)`,
        # so the arm exists solely because `match purpose` must be exhaustive.
        # It is inventoried rather than removed because every alternative is
        # worse -- folding it into the `ClaimAdaptor => None` arm would give
        # Sponsor a silent success shape, and panicking violates fail-closed.
        # The `Canonical` variant is a loose fit inherited from that entry
        # gate, which rejects the same condition with the same variant; a
        # tighter vocabulary must move both sites together, which is a code
        # question and not an inventory one.  The reason Sponsor can never be
        # signed here is shape, not custody: `template_hash_for_purpose`
        # slices the payload into three template slots and Sponsor has none,
        # and both phase mappings send it to `FailedClosed`.
        (
            "crates/dom-scriptless-store/src/runtime/linux/session_store.rs",
            "PurposeV1::Sponsor => return Err(Box::new(SessionStoreError::Canonical)),",
        ): 1,
    }
)

# Whole-file hashes complement the lexical denylist.  A harmless-looking
# authority rename must not turn an approved contract body into an unreviewed
# one while evading the known-token scan.
I2_CONTRACT_SHA256: dict[str, str] = {
    "contracts/src/ConditionLockCoreV2.sol": (
        "e13eb59a8232aaa06385fa6e979e336ef6bd3659132c9c687ac18cfa751410f9"
    ),
    "contracts/src/ConditionLockERC20V2.sol": (
        "9bb1511b14628af7aa55e3b68a1f684c2905b4265baf18fdd9d263837d1538c6"
    ),
    "contracts/src/ConditionLockV2.sol": (
        "d989d1600b41be84a444990d278a4b3fdd08a17dbc8b5f3ce4321cd5d3a64414"
    ),
    "contracts/src/LockBinding.sol": (
        "f625a5210574bce5807dff4dc787d6c085ad6dbdb0f004c305e0a5d44e415a9d"
    ),
}

# Both former None sentinels were resolved on 2026-08-30: each source was
# frozen, its Sponsor surface reviewed against the question the line allowlist
# cannot answer, and its digest inserted by explicit act.  The reviews are not
# interchangeable and the record says so.  For the Store file the digest is
# load-bearing: `is_strict_v1_authorized` and `require_strict_phase1` decide
# Sponsor in nine lines that never spell the token, so the line allowlist is
# blind to them and only the whole-file digest covers them.  For the actuator
# bridge the allowlist already sees the entire decision surface -- one Err arm,
# two callers, no PurposeV1 ever constructed in that crate -- so the digest
# buys shape instead: the decision cannot be moved, renamed, or have its two
# callers diverted without detection.  It is worth having; it is not worth
# having for the same reason.  A new None here is still a fail-closed
# sentinel, not a wildcard.
#
# Re-frozen on 2026-08-31 after the Stage 6 typed Store/actuator integration.
# The exact Sponsor inventory above remained unchanged: the actuator still
# maps Sponsor only to CapabilityMismatch, and every Store signing path either
# calls require_strict_phase1/is_strict_v1_authorized or terminates in an
# explicit FailedClosed/error arm.  Updating these digests records that review;
# it does not expand the allowed Sponsor surface.
#
# Re-frozen on 2026-09-02 in the Stage 13 guard pass, after the guard had sat
# red since the stage-7 composition root.  What the diff against the
# 2026-08-31 digests contains, file by file, and what it does not.  The six
# adaptor, actuator and crypto files changed for exactly one reason:
# `PurposeV1::RefundAdaptor = 0x05` (NAR-DC-P1-009), a new authorized purpose
# that widens every `ClaimAdaptor` grammar arm to `ClaimAdaptor |
# RefundAdaptor` and maps to `PresignRefund` in the actuator.  Sponsor is
# untouched in all six: still `CapabilityMismatch`, still `PurposeNotAuthorized`
# from `require_strict_phase1`, still refused by `validate_adaptor_grammar` and
# `finalize_plain_signature_v1`, still only a byte in the crypto envelope.  The
# Store file grew by the EVM action transport records, the post-anchor
# claim-signing owner reservation and the resumed production open; its five
# Sponsor arms and ten strict-gate call sites are byte-identical to the frozen
# text, and the RefundAdaptor arms it gained sit beside `Refund`, never beside
# `Sponsor`.  `f7_wallet.rs` enters the inventory because the restored
# compositor names Sponsor (three fail-closed arms, inventoried above); the
# operational ladder migration will change that file and must re-freeze it.
F1_SPONSOR_FILE_SHA256: dict[str, str | None] = {
    "crates/dom-actuator/src/contracts.rs": (
        "c1232d2d6dc8fe4e390d1358bfa797bdf4fee17bc7eed3ef601a4df35ef2c083"
    ),
    "crates/dom-adaptor/src/context.rs": (
        "5b9c9486caa18c0599a8995d8e805a7c641233bc978eaa72e9a40fb56324b22d"
    ),
    "crates/dom-adaptor/src/messages.rs": (
        "2149fd13cf3ba2d8c1a8b31f92d9ee0f59ee44a0d4da54696db5dbb009d374c4"
    ),
    "crates/dom-adaptor/src/nonce.rs": (
        "d9060a256c99b66b504d5436f44b75b513ce12dbb4b773cd8ec4c515c2f53f72"
    ),
    "crates/dom-adaptor/src/transcript.rs": (
        "a9ba40ebcccb06216f489fe0d6502d293c5cebddf1f3f70a471cfcfb1fbf30dd"
    ),
    "crates/dom-scriptless-crypto/src/storage.rs": (
        "5d7bc7c2a625e63ccbb6764f21ce86c6f1ed12eb0e9857d4b00d5ae1376c5266"
    ),
    "crates/dom-scriptless-store/src/runtime/linux/session_store.rs": (
        "1bbe92593bbcfbc610796c61e1fa74c3caff8996fcab2ef5ca412f0ceaad50ba"
    ),
    "crates/dom-leg/src/f7_wallet.rs": (
        "95085209446f2fb56993519e9c9e2926a20e4e186394357ea7aa7a8afb25cab4"
    ),
}

ANTI_POWER = re.compile(
    r"\b(?:"
    r"admin_key|adminKey|onlyOwner|guardian|pause_all|founder|"
    r"only_owner|pauseAll|proxy_admin|access_control|"
    r"Ownable|AccessControl|ProxyAdmin|Pausable|UUPSUpgradeable|"
    r"TransparentUpgradeableProxy|DEFAULT_ADMIN_ROLE|grantRole|revokeRole|"
    r"default_admin_role|grant_role|revoke_role|"
    r"upgradeTo|upgradeToAndCall|upgrade_to|upgrade_to_and_call|"
    r"selfdestruct|self_destruct|suicide|delegatecall"
    r")\b",
    re.IGNORECASE,
)

I14_PATTERN = re.compile(r"\.\s*(?:unwrap\s*\(\s*\)|expect\s*\()")
I6_PATTERN = re.compile(r"\b(?:println|eprintln|dbg)\s*!")
F1_SPONSOR_PATTERN = re.compile(r"\bPurposeV1?\s*::\s*Sponsor\b")

MANUAL_SIGNET_RUNNERS = frozenset(
    {
        "scripts/f5-signet-custom-e2e.sh",
        "scripts/f5-signet-public-e2e.sh",
    }
)
_AUTOMATION_PATH = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<path>"
    r"(?:(?:\.\.?/)+[A-Za-z0-9_./+-]+)|"
    r"(?:(?:scripts|contracts/scripts|\.github/actions)/[A-Za-z0-9_./+-]+)|"
    r"(?:[A-Za-z0-9_.+-]+\.(?:sh|bash|py|ya?ml|mk))"
    r")"
)
_DYNAMIC_REPOSITORY_DISPATCH = (
    re.compile(r"(?m)^[ \t]*(?:source|\.)[ \t]+[\"']?\$"),
    re.compile(r"(?<![A-Za-z0-9_.-])(?:bash|sh|python|python3)[ \t]+[\"']?\$"),
    re.compile(
        r"(?im)^[ \t]*(?:(?:command|exec|env)[ \t]+)?[\"']?\$(?:"
        r"[A-Za-z0-9_]*(?:runner|script|command|cmd|entrypoint|target)[A-Za-z0-9_]*|"
        r"\{[A-Za-z0-9_]*(?:runner|script|command|cmd|entrypoint|target)"
        r"[A-Za-z0-9_]*(?:\[@\])?\})[\"']?(?:[ \t]|$)"
    ),
    re.compile(r"\b(?:bash|sh)[ \t]+-c(?:[ \t]|$)"),
    re.compile(r"\beval(?:[ \t]|$)"),
    re.compile(r"(?:^|[^A-Za-z0-9_])scripts/[^ \t\r\n\"']*\$"),
    re.compile(
        r"(?im)^[ \t]*(?:[A-Za-z0-9_]*(?:runner|script|command|cmd|entrypoint)[A-Za-z0-9_]*)="
        r"[^\r\n]*(?:\$(?:repo|REPO_ROOT|GITHUB_WORKSPACE)|"
        r"\$\{(?:repo|REPO_ROOT|GITHUB_WORKSPACE)\})/[^\r\n]*\$"
    ),
    re.compile(
        r"(?m)^[ \t]*[\"']?(?:\$(?:repo|REPO_ROOT|GITHUB_WORKSPACE)|"
        r"\$\{(?:repo|REPO_ROOT|GITHUB_WORKSPACE)\})/[^\r\n]*\$"
    ),
    re.compile(r"(?m)^[ \t]*(?:run|uses):[ \t]*[\"']?\$\{\{"),
    re.compile(r"(?m)^[ \t]*\$\{\{[^\r\n]+\}\}"),
    re.compile(r"(?m)^(?:-?include|sinclude)[ \t]+[^\r\n]*\$"),
    re.compile(r"(?m)^\t[ \t]*\$[({][A-Za-z_][A-Za-z0-9_]*[)}](?:[ \t]|$)"),
)
_LIVE_SIGNET_COMMAND = re.compile(
    r"\b(?:bitcoin-cli|bitcoind)\b[^\r\n]*(?:^|[ \t])-(?:chain=)?signet(?:[ \t]|$)",
    re.MULTILINE,
)
_SIGNET_AUTOMATION_TOKEN = re.compile(r"\bsignet\b", re.IGNORECASE)
CUSTOM_SIGNET_CHALLENGE_HEX = (
    "21030f293b15c1014a5a747712be70543883a204e546fef03fea9ea6d939f6e9f4e0ac"
)


@dataclasses.dataclass(frozen=True, order=True)
class Finding:
    """One attributable policy failure."""

    path: str
    line: int
    message: str


@dataclasses.dataclass(frozen=True)
class CheckResult:
    """Result of one named guard."""

    name: str
    findings: tuple[Finding, ...]
    note: str = ""

    @property
    def passed(self) -> bool:
        """Whether this guard has no finding."""

        return not self.findings


@dataclasses.dataclass(frozen=True)
class RustSource:
    """A Rust source with comments/strings and test-only lines classified."""

    path: pathlib.Path
    relative_path: str
    original_lines: tuple[str, ...]
    code: str
    commentless: str
    code_lines: tuple[str, ...]
    commentless_lines: tuple[str, ...]


_RUST_LEXEME = re.compile(
    r"//|/\*|(?<![A-Za-z0-9_])(?:br|rb|cr|rc|r)#{0,255}\"|"
    r"(?<![A-Za-z0-9_])b\"|\"|'"
)
_BLOCK_COMMENT_DELIMITER = re.compile(r"/\*|\*/")
_NON_NEWLINE = re.compile(r"[^\r\n]")


def _masked(value: str) -> str:
    return _NON_NEWLINE.sub(" ", value)


def _raw_string_end(source: str, start: int) -> int | None:
    """Return the end of a Rust raw string starting at *start*, if any."""

    index = start
    if any(source.startswith(prefix, index) for prefix in ("br", "rb", "cr", "rc")):
        index += 2
    elif source.startswith("r", index):
        index += 1
    else:
        return None
    hashes = 0
    while index < len(source) and source[index] == "#":
        hashes += 1
        index += 1
    if index >= len(source) or source[index] != '"':
        return None
    terminator = '"' + ("#" * hashes)
    found = source.find(terminator, index + 1)
    return len(source) if found < 0 else found + len(terminator)


def _quoted_end(source: str, quote: int) -> int:
    index = quote + 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
            continue
        if source[index] == '"':
            return index + 1
        index += 1
    return len(source)


def _char_end(source: str, quote: int) -> int | None:
    """Recognize a Rust character literal without mistaking a lifetime."""

    index = quote + 1
    if index >= len(source) or source[index] in "\r\n":
        return None
    if source[index] == "\\":
        index += 1
        if index >= len(source):
            return None
        if source[index] == "u" and source[index + 1 : index + 2] == "{":
            closing = source.find("}", index + 2)
            if closing < 0 or "\n" in source[index:closing]:
                return None
            index = closing + 1
        elif source[index] == "x":
            index += 3
        else:
            index += 1
    else:
        index += 1
    if index < len(source) and source[index] == "'":
        return index + 1
    return None


def sanitize_source(source: str, *, strip_strings: bool) -> str:
    """Remove Rust comments and optionally literals while retaining line shape."""

    pieces: list[str] = []
    emitted = 0
    scan = 0

    def replace(start: int, end: int) -> None:
        nonlocal emitted
        pieces.append(source[emitted:start])
        pieces.append(_masked(source[start:end]))
        emitted = end

    while match := _RUST_LEXEME.search(source, scan):
        start = match.start()
        token = match.group(0)
        if token == "//":
            end = source.find("\n", start + 2)
            end = len(source) if end < 0 else end
            replace(start, end)
            scan = end
            continue
        if token == "/*":
            depth = 1
            end = start + 2
            while depth:
                delimiter = _BLOCK_COMMENT_DELIMITER.search(source, end)
                if delimiter is None:
                    end = len(source)
                    break
                end = delimiter.end()
                depth += 1 if delimiter.group(0) == "/*" else -1
            replace(start, end)
            scan = end
            continue

        raw_end = _raw_string_end(source, start)
        if raw_end is not None:
            if strip_strings:
                replace(start, raw_end)
            scan = raw_end
            continue

        quote_index = start + 1 if token == 'b"' else start
        if token.endswith('"'):
            end = _quoted_end(source, quote_index)
            if strip_strings:
                replace(start, end)
            scan = end
            continue

        end = _char_end(source, start)
        if end is not None:
            if strip_strings:
                replace(start, end)
            scan = end
        else:
            # A Rust lifetime (for example &'a) is code, not a literal.
            scan = match.end()

    pieces.append(source[emitted:])
    return "".join(pieces)


def sanitize_solidity_source(source: str) -> str:
    """Mask Solidity comments and literals while preserving byte/line shape.

    Solidity block comments terminate at the first ``*/``; unlike Rust they do
    not nest.  Sharing the Rust comment walker here would let a fake nested
    opener hide live Solidity from the authority scan.
    """

    pieces: list[str] = []
    emitted = 0
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = len(source) if end < 0 else end
        elif source.startswith("/*", index):
            closing = source.find("*/", index + 2)
            end = len(source) if closing < 0 else closing + 2
        elif source[index] in {'"', "'"}:
            quote = source[index]
            end = index + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == quote:
                    end += 1
                    break
                end += 1
        else:
            index += 1
            continue
        pieces.append(source[emitted:index])
        pieces.append(_masked(source[index:end]))
        emitted = end
        index = end
    pieces.append(source[emitted:])
    return "".join(pieces)


def _split_cfg_arguments(value: str) -> list[str]:
    arguments: list[str] = []
    depth = 0
    start = 0
    for index, character in enumerate(value):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "," and depth == 0:
            arguments.append(value[start:index])
            start = index + 1
    arguments.append(value[start:])
    return [argument for argument in arguments if argument]


def _cfg_implies_any(expression: str, required_atoms: frozenset[str]) -> bool:
    """Return true only when *expression* implies one of *required_atoms*."""

    value = re.sub(r"\s+", "", expression)
    if value.startswith("cfg(") and value.endswith(")"):
        value = value[4:-1]
    if value in required_atoms:
        return True
    for operator in ("all", "any", "not"):
        prefix = operator + "("
        if value.startswith(prefix) and value.endswith(")"):
            children = _split_cfg_arguments(value[len(prefix) : -1])
            if operator == "all":
                return any(_cfg_implies_any(child, required_atoms) for child in children)
            if operator == "any":
                return bool(children) and all(
                    _cfg_implies_any(child, required_atoms) for child in children
                )
            return False
    return False


def cfg_implies_test(expression: str) -> bool:
    """Return true only when a cfg expression cannot hold outside cfg(test)."""

    return _cfg_implies_any(expression, frozenset({"test"}))


def cfg_implies_nonproduction(expression: str) -> bool:
    """Recognize cfgs that the compiler itself reserves for test targets.

    ``fuzzing`` is an ordinary user cfg.  A build script or ``RUSTFLAGS`` can
    enable it in a release build, so it is never evidence that code is absent
    from production.
    """

    return cfg_implies_test(expression)


def _matching_delimiter(source: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    for index in range(start, len(source)):
        if source[index] == opening:
            depth += 1
        elif source[index] == closing:
            depth -= 1
            if depth == 0:
                return index + 1
    return len(source)


def _skip_attributes(source: str, start: int) -> int:
    index = start
    while True:
        while index < len(source) and source[index].isspace():
            index += 1
        if source.startswith("#[", index):
            index = _matching_delimiter(source, index + 1, "[", "]")
            continue
        return index


def _item_end(source: str, start: int) -> int:
    """Find the end of the item following an attribute in sanitized Rust."""

    index = start
    paren = 0
    bracket = 0
    while index < len(source):
        character = source[index]
        if character == "(":
            paren += 1
        elif character == ")":
            paren = max(0, paren - 1)
        elif character == "[":
            bracket += 1
        elif character == "]":
            bracket = max(0, bracket - 1)
        elif character == "{" and paren == 0 and bracket == 0:
            return _matching_delimiter(source, index, "{", "}")
        elif character == ";" and paren == 0 and bracket == 0:
            return index + 1
        index += 1
    return len(source)


def _test_only_spans(sanitized: str) -> tuple[tuple[int, int], ...]:
    """Locate exact spans provably absent from non-test builds."""

    spans: list[tuple[int, int]] = []
    attribute = re.compile(r"#\s*\[\s*(cfg\s*\(|test\s*\])")
    for match in attribute.finditer(sanitized):
        token = match.group(1)
        if token.startswith("test"):
            attribute_end = sanitized.find("]", match.start())
            if attribute_end < 0:
                continue
            attribute_end += 1
            is_test = True
        else:
            open_paren = sanitized.find("(", match.start(), match.end() + 1)
            if open_paren < 0:
                continue
            cfg_end = _matching_delimiter(sanitized, open_paren, "(", ")")
            expression = sanitized[open_paren + 1 : cfg_end - 1]
            attribute_end = sanitized.find("]", cfg_end)
            if attribute_end < 0:
                continue
            attribute_end += 1
            is_test = cfg_implies_nonproduction(expression)
        if not is_test:
            continue
        item_start = _skip_attributes(sanitized, attribute_end)
        spans.append((match.start(), _item_end(sanitized, item_start)))

    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _mask_spans(source: str, spans: Sequence[tuple[int, int]]) -> str:
    pieces: list[str] = []
    emitted = 0
    for start, end in spans:
        pieces.append(source[emitted:start])
        pieces.append(_masked(source[start:end]))
        emitted = end
    pieces.append(source[emitted:])
    return "".join(pieces)

def mask_test_only_items(sanitized: str) -> str:
    """Mask only the attributed item, never every byte on a shared line."""

    return _mask_spans(sanitized, _test_only_spans(sanitized))


def test_only_line_numbers(sanitized: str) -> frozenset[int]:
    """Compatibility view of test-only spans for diagnostics and tests."""

    lines: set[int] = set()
    for start, end in _test_only_spans(sanitized):
        first = sanitized.count("\n", 0, start) + 1
        last = sanitized.count("\n", 0, end) + 1
        lines.update(range(first, last + 1))
    return frozenset(lines)


def _read_workspace(root: pathlib.Path) -> tuple[list[str], dict[str, str]]:
    manifest = root / "Cargo.toml"
    try:
        document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        members = document["workspace"]["members"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"cannot read workspace members: {error}") from error
    if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
        raise ValueError("workspace members must be a string array")
    if len(set(members)) != len(members):
        raise ValueError("workspace members contain duplicates")

    names: dict[str, str] = {}
    for member in members:
        member_path = pathlib.PurePosixPath(member)
        if member_path.is_absolute() or ".." in member_path.parts or str(member_path) != member:
            raise ValueError(f"workspace member is not a canonical in-tree path: {member}")
        member_root = root / member
        try:
            member_root.resolve(strict=True).relative_to(root.resolve(strict=True))
        except (OSError, ValueError) as error:
            raise ValueError(f"workspace member escapes or is absent: {member}") from error
        if member_root.is_symlink() or not member_root.is_dir():
            raise ValueError(f"workspace member is not a regular in-tree directory: {member}")
        member_manifest = root / member / "Cargo.toml"
        try:
            package = tomllib.loads(member_manifest.read_text(encoding="utf-8"))["package"]
            name = package["name"]
        except (OSError, KeyError, tomllib.TOMLDecodeError) as error:
            raise ValueError(f"cannot read {member}/Cargo.toml: {error}") from error
        if not isinstance(name, str) or not name:
            raise ValueError(f"{member}/Cargo.toml has no package name")
        names[member] = name
    return members, names


def _workspace_manifests(root: pathlib.Path) -> tuple[pathlib.Path, ...]:
    members, _ = _read_workspace(root)
    return (root / "Cargo.toml", *(root / member / "Cargo.toml" for member in members))


# Manifests outside `[workspace] members` (per-crate fuzz workspaces, labs, the
# `exclude`d desktop wallet) resolve their own graphs and can never unify
# features into the production build, but they are exercised or shipped code
# and the evidence-only / C1a boundaries must still see them.  They are
# discovered on disk rather than listed, so a new parallel workspace cannot
# appear silently; `target`, `.git` and vendored trees are pruned.
_MANIFEST_SCAN_PRUNE = frozenset({".git", "target", "node_modules", "vendor", "dist"})


def _manifests_on_disk(root: pathlib.Path) -> tuple[pathlib.Path, ...]:
    found: list[pathlib.Path] = []
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name not in _MANIFEST_SCAN_PRUNE and not entry.is_symlink():
                    stack.append(entry)
            elif entry.name == "Cargo.toml":
                found.append(entry)
    return tuple(sorted(found))


def _guarded_manifests(root: pathlib.Path) -> tuple[pathlib.Path, ...]:
    """Workspace manifests first, then every other Cargo.toml found on disk."""

    listed = _workspace_manifests(root)
    seen = {path.resolve() for path in listed}
    extras = tuple(path for path in _manifests_on_disk(root) if path.resolve() not in seen)
    return (*listed, *extras)


def production_member_paths(root: pathlib.Path) -> tuple[str, ...]:
    """Return every product-layer member; new members are covered by default."""

    members, _ = _read_workspace(root)
    missing_node = NODE_MEMBERS.difference(members)
    missing_harness = HARNESS_MEMBERS.difference(members)
    if missing_node or missing_harness:
        missing = sorted(missing_node | missing_harness)
        raise ValueError("workspace classification drift: " + ", ".join(missing))
    return tuple(
        member
        for member in members
        if member not in NODE_MEMBERS and member not in HARNESS_MEMBERS
    )


def layer_package_names(root: pathlib.Path) -> tuple[str, ...]:
    """Return production plus acceptance package names for local layer CI."""

    members, names = _read_workspace(root)
    missing_node = NODE_MEMBERS.difference(members)
    missing_harness = HARNESS_MEMBERS.difference(members)
    if missing_node or missing_harness:
        missing = sorted(missing_node | missing_harness)
        raise ValueError("workspace classification drift: " + ", ".join(missing))
    return tuple(names[member] for member in members if member not in NODE_MEMBERS)


def node_member_paths(root: pathlib.Path) -> tuple[str, ...]:
    """Return the frozen node paths after checking workspace classification."""

    members, _ = _read_workspace(root)
    missing = NODE_MEMBERS.difference(members)
    if missing:
        raise ValueError("workspace classification drift: " + ", ".join(sorted(missing)))
    return tuple(sorted(NODE_MEMBERS))


def _member_rust_paths(member_root: pathlib.Path) -> tuple[pathlib.Path, ...]:
    """Enumerate every Rust file below a productive workspace member.

    Target classification happens after enumeration.  In particular, a path
    called ``tests`` below ``src`` is not special, and a top-level integration
    test is still visible to the reachability analysis in case it points back
    at a productive source with ``#[path]``.
    """

    paths: list[pathlib.Path] = []
    for path in member_root.rglob("*.rs"):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Rust source is not a regular in-tree file: {path}")
        paths.append(path)
    return tuple(sorted(paths))


_OUT_OF_LINE_MODULE = re.compile(
    r"(?m)^[ \t]*"
    r"(?P<attributes>(?:#\s*\[[^\]\r\n]*\][ \t]*(?:\r?\n[ \t]*)?)*)"
    r"(?:(?:pub(?:\([^\r\n)]*\))?|unsafe)\s+)*"
    r"mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;"
)
_DIRECT_PATH_ATTRIBUTE = re.compile(
    r"#\s*\[\s*path\s*=\s*\"(?P<path>[^\"\r\n]+)\"\s*\]"
)


def _is_conventional_test_target(path: pathlib.Path, member_root: pathlib.Path) -> bool:
    parts = path.relative_to(member_root).parts
    return bool(parts) and parts[0] in {"tests", "benches", "fuzz"}


def _is_standard_product_root(path: pathlib.Path, member_root: pathlib.Path) -> bool:
    relative = path.relative_to(member_root)
    parts = relative.parts
    if relative.as_posix() in {"build.rs", "src/lib.rs", "src/main.rs"}:
        return True
    if len(parts) == 3 and parts[:2] == ("src", "bin"):
        return True
    if len(parts) >= 4 and parts[:2] == ("src", "bin") and path.name == "main.rs":
        return True
    if parts and parts[0] == "examples":
        return len(parts) == 2 or path.name == "main.rs"
    return False


def _implicit_module_candidates(
    declaring: pathlib.Path,
    name: str,
    member_root: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path]:
    if (
        _is_standard_product_root(declaring, member_root)
        or _is_conventional_test_target(declaring, member_root)
        or declaring.name == "mod.rs"
    ):
        base = declaring.parent
    else:
        base = declaring.parent / declaring.stem
    return base / f"{name}.rs", base / name / "mod.rs"


def _module_edges(
    path: pathlib.Path,
    member_root: pathlib.Path,
    all_paths: frozenset[pathlib.Path],
) -> tuple[tuple[pathlib.Path, bool], ...]:
    """Return resolved out-of-line module edges and their test-only cfg bit.

    Only declarations whose path is statically canonical are used to prove a
    whole file test-only.  Anything malformed, generated or unresolved stays
    in the fail-closed fallback scan.
    """

    source = path.read_text(encoding="utf-8")
    code = sanitize_source(source, strip_strings=True)
    commentless = sanitize_source(source, strip_strings=False)
    test_spans = _test_only_spans(code)
    source_is_test_target = _is_conventional_test_target(path, member_root)
    member_resolved = member_root.resolve(strict=True)
    edges: list[tuple[pathlib.Path, bool]] = []
    for match in _OUT_OF_LINE_MODULE.finditer(code):
        attributes = commentless[match.start("attributes") : match.end("attributes")]
        explicit_paths = [item.group("path") for item in _DIRECT_PATH_ATTRIBUTE.finditer(attributes)]
        if len(explicit_paths) > 1:
            continue
        if explicit_paths:
            declared = pathlib.PurePosixPath(explicit_paths[0])
            if declared.is_absolute():
                continue
            candidates = (path.parent / pathlib.Path(*declared.parts),)
        else:
            candidates = _implicit_module_candidates(
                path, match.group("name"), member_root
            )

        is_test_edge = source_is_test_target or any(
            start <= match.start() < end for start, end in test_spans
        )
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(member_resolved)
            except (OSError, ValueError):
                # An unresolved declaration cannot justify subtracting any
                # in-member file.  A productive escape is rejected below by
                # the source scanner only when the file is actually present;
                # Cargo itself rejects an absent target.
                continue
            if resolved in all_paths:
                edges.append((resolved, is_test_edge))
    return tuple(edges)


def _whole_test_only_paths(
    member_root: pathlib.Path, paths: Sequence[pathlib.Path]
) -> frozenset[pathlib.Path]:
    """Prove whole-file test-only reachability; ambiguous files stay product.

    Product reachability always wins over test reachability.  Files that are
    not reached by any literal module edge are treated as productive roots,
    which is the fail-closed fallback for custom Cargo targets and generated
    or macro-driven module layouts.
    """

    all_paths = frozenset(path.resolve(strict=True) for path in paths)
    edges_by_source: dict[pathlib.Path, tuple[tuple[pathlib.Path, bool], ...]] = {}
    all_targets: set[pathlib.Path] = set()
    for path in all_paths:
        edges = _module_edges(path, member_root, all_paths)
        edges_by_source[path] = edges
        all_targets.update(target for target, _ in edges)

    conventional_tests = {
        path for path in all_paths if _is_conventional_test_target(path, member_root)
    }
    product_reachable = {
        path for path in all_paths if _is_standard_product_root(path, member_root)
    }
    product_reachable.update(all_paths.difference(all_targets, conventional_tests))

    pending = list(product_reachable)
    while pending:
        source = pending.pop()
        for target, test_edge in edges_by_source.get(source, ()):
            if test_edge or target in product_reachable:
                continue
            product_reachable.add(target)
            pending.append(target)

    test_reachable = set(conventional_tests)
    for edges in edges_by_source.values():
        test_reachable.update(target for target, test_edge in edges if test_edge)
    pending = list(test_reachable)
    while pending:
        source = pending.pop()
        for target, _ in edges_by_source.get(source, ()):
            if target in test_reachable:
                continue
            test_reachable.add(target)
            pending.append(target)

    return frozenset(test_reachable.difference(product_reachable))


def load_rust_sources(root: pathlib.Path) -> tuple[RustSource, ...]:
    """Load every member source, masking only positively proven test code.

    A global ``test path -> source path`` subtraction is never performed.
    Top-level test/bench/fuzz targets and test-only modules are classified by
    reachability, while a productive edge to the same file always wins.  Every
    unresolved or unreferenced ``.rs`` file falls back to the product scan.
    """

    paths: list[pathlib.Path] = []
    whole_test_only: set[pathlib.Path] = set()
    for member in production_member_paths(root):
        member_root = root / member
        member_paths = _member_rust_paths(member_root)
        paths.extend(member_paths)
        whole_test_only.update(_whole_test_only_paths(member_root, member_paths))

    loaded: list[RustSource] = []
    for path in sorted(paths):
        source = path.read_text(encoding="utf-8")
        raw_code = sanitize_source(source, strip_strings=True)
        spans = (
            ((0, len(raw_code)),)
            if path.resolve(strict=True) in whole_test_only
            else _test_only_spans(raw_code)
        )
        code = _mask_spans(raw_code, spans)
        commentless = _mask_spans(
            sanitize_source(source, strip_strings=False), spans
        )
        loaded.append(
            RustSource(
                path=path,
                relative_path=path.relative_to(root).as_posix(),
                original_lines=tuple(source.splitlines()),
                code=code,
                commentless=commentless,
                code_lines=tuple(code.splitlines()),
                commentless_lines=tuple(commentless.splitlines()),
            )
        )
    return tuple(loaded)


def _signature(source: RustSource, line_number: int) -> tuple[str, str]:
    return source.relative_path, source.original_lines[line_number - 1].strip()


def _line_at(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _cargo_build_directive(source: RustSource, match: re.Match[str]) -> bool:
    """Recognize Cargo's build-script protocol, not general stdout."""

    if source.path.name != "build.rs" or not match.group(0).lstrip().startswith("println"):
        return False
    tail = source.commentless[match.start() : match.start() + 256]
    return re.match(r'println\s*!\s*\(\s*"cargo(?:::|:)', tail, re.DOTALL) is not None


def _sponsor_context_is_rejection_or_registry(
    relative_path: str, code: str, offset: int
) -> bool:
    line = _line_at(code, offset)
    lines = code.splitlines()
    window = "\n".join(lines[max(0, line - 4) : min(len(lines), line + 5)])
    rejection = re.search(
        r"Sponsor(?:(?!=>).)*=>\s*(?:\{\s*)?(?:return\s+)?(?:Err\s*\(|\[\s*0\s*;\s*32\s*\]|SessionPhaseV1::FailedClosed)",
        window,
        re.DOTALL,
    )
    if rejection is not None or (
        "Sponsor.to_byte()" in window and re.search(r"(?:return\s+)?Err\s*\(", window)
    ):
        return True
    if relative_path == "crates/dom-scriptless-crypto/src/storage.rs":
        prefix = "\n".join(lines[max(0, line - 20) : line])
        functions = re.findall(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", prefix)
        return bool(functions) and functions[-1] in {"parse_purpose", "canonical_purpose_byte"}
    return False


def _exact_allowlist_findings(
    name: str,
    actual: collections.Counter[tuple[str, str]],
    expected: collections.Counter[tuple[str, str]],
) -> list[Finding]:
    findings: list[Finding] = []
    for signature, count in sorted((actual - expected).items()):
        path, line = signature
        findings.append(Finding(path, 0, f"{name}: unreviewed production use x{count}: {line}"))
    for signature, count in sorted((expected - actual).items()):
        path, line = signature
        findings.append(
            Finding(path, 0, f"{name}: frozen allowance disappeared x{count}; remove it explicitly: {line}")
        )
    return findings


def _frozen_sha256_findings(
    root: pathlib.Path,
    name: str,
    expected: dict[str, str | None],
    actual_paths: Iterable[str],
) -> list[Finding]:
    """Verify an exact file inventory and review-pinned whole-file digests."""

    findings: list[Finding] = []
    expected_paths = set(expected)
    actual = set(actual_paths)
    for relative in sorted(actual - expected_paths):
        findings.append(Finding(relative, 0, f"{name}: unreviewed file in frozen inventory"))
    for relative in sorted(expected_paths - actual):
        findings.append(Finding(relative, 0, f"{name}: frozen file is absent"))

    for relative in sorted(expected_paths & actual):
        expected_digest = expected[relative]
        if expected_digest is None:
            findings.append(
                Finding(relative, 0, f"{name}: SHA-256 awaits explicit post-handoff review")
            )
            continue
        if re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
            findings.append(Finding(relative, 0, f"{name}: expected SHA-256 is invalid"))
            continue
        path = root / relative
        if path.is_symlink() or not path.is_file():
            findings.append(Finding(relative, 0, f"{name}: frozen source is not a regular file"))
            continue
        try:
            actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as error:
            findings.append(Finding(relative, 0, f"{name}: cannot hash source: {error}"))
            continue
        if actual_digest != expected_digest:
            findings.append(
                Finding(
                    relative,
                    0,
                    f"{name}: SHA-256 changed (expected {expected_digest}, got {actual_digest})",
                )
            )
    return findings


def check_source_policies(
    root: pathlib.Path,
    *,
    _sources: tuple[RustSource, ...] | None = None,
    _source_error: str | None = None,
) -> tuple[CheckResult, ...]:
    """Run anti-power, panic, print and Sponsor checks over product Rust/Solidity."""

    if _source_error is not None:
        finding = Finding("Cargo.toml", 0, _source_error)
        return tuple(
            CheckResult(name, (finding,))
            for name in ("I2 anti-power", "I14 panic paths", "I6 raw output", "F1 Sponsor")
        )
    if _sources is None:
        try:
            sources = load_rust_sources(root)
        except ValueError as error:
            finding = Finding("Cargo.toml", 0, str(error))
            return tuple(
                CheckResult(name, (finding,))
                for name in ("I2 anti-power", "I14 panic paths", "I6 raw output", "F1 Sponsor")
            )
    else:
        sources = _sources

    anti_power: list[Finding] = []
    i14_actual: collections.Counter[tuple[str, str]] = collections.Counter()
    i6_actual: collections.Counter[tuple[str, str]] = collections.Counter()
    sponsor_actual: collections.Counter[tuple[str, str]] = collections.Counter()
    sponsor_semantics: list[Finding] = []
    sponsor_paths: set[str] = set()

    for source in sources:
        # Authority names are identifiers.  Comments and literals are removed
        # so an error message cannot become a false authority surface.
        if re.search(r"\bSponsor\b", source.code):
            sponsor_paths.add(source.relative_path)
        for number, code in enumerate(source.code_lines, start=1):
            for match in ANTI_POWER.finditer(code):
                anti_power.append(
                    Finding(source.relative_path, number, f"forbidden authority surface: {match.group(0)}")
                )
        for match in I14_PATTERN.finditer(source.code):
            i14_actual[_signature(source, _line_at(source.code, match.start()))] += 1
        for match in I6_PATTERN.finditer(source.code):
            if _cargo_build_directive(source, match):
                continue
            i6_actual[_signature(source, _line_at(source.code, match.start()))] += 1
        for match in F1_SPONSOR_PATTERN.finditer(source.code):
            number = _line_at(source.code, match.start())
            sponsor_actual[_signature(source, number)] += 1
            if not _sponsor_context_is_rejection_or_registry(
                source.relative_path, source.code, match.start()
            ):
                sponsor_semantics.append(
                    Finding(
                        source.relative_path,
                        number,
                        "Sponsor occurrence lacks local rejection/closed-registry shape",
                    )
                )

    contract_paths: list[str] = []
    contracts = root / "contracts" / "src"
    if not contracts.is_dir():
        anti_power.append(Finding("contracts/src", 0, "contract source directory is absent"))
    else:
        for path in sorted(contracts.rglob("*.sol")):
            relative = path.relative_to(root).as_posix()
            contract_paths.append(relative)
            if path.is_symlink() or not path.is_file():
                anti_power.append(
                    Finding(relative, 0, "contract source is not regular")
                )
                continue
            try:
                source_text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                anti_power.append(Finding(relative, 0, f"cannot read contract source: {error}"))
                continue
            code = sanitize_solidity_source(source_text)
            for number, line in enumerate(code.splitlines(), start=1):
                for match in ANTI_POWER.finditer(line):
                    anti_power.append(
                        Finding(
                            relative,
                            number,
                            f"forbidden authority surface: {match.group(0)}",
                        )
                    )

    anti_power.extend(
        _frozen_sha256_findings(
            root, "I2 contract inventory", I2_CONTRACT_SHA256, contract_paths
        )
    )
    sponsor_semantics.extend(
        _frozen_sha256_findings(
            root,
            "F1 Sponsor source freeze",
            F1_SPONSOR_FILE_SHA256,
            sponsor_paths,
        )
    )

    return (
        CheckResult("I2 anti-power", tuple(sorted(anti_power))),
        CheckResult(
            "I14 unwrap/expect outside tests",
            tuple(_exact_allowlist_findings("I14", i14_actual, I14_ALLOWLIST)),
        ),
        CheckResult(
            "I6 println/eprintln/dbg outside tests",
            tuple(_exact_allowlist_findings("I6", i6_actual, I6_ALLOWLIST)),
        ),
        CheckResult(
            "F1 Sponsor is frozen with local rejection/registry shape",
            tuple(
                _exact_allowlist_findings(
                    "F1 Sponsor", sponsor_actual, F1_SPONSOR_ALLOWLIST
                )
                + sponsor_semantics
            ),
        ),
    )


def _walk_dependency_tables(document: dict, prefix: tuple[str, ...] = ()) -> Iterable[tuple[str, dict]]:
    for key, value in document.items():
        if not isinstance(value, dict):
            continue
        next_prefix = prefix + (key,)
        if key in {"dependencies", "dev-dependencies", "build-dependencies"}:
            yield ".".join(next_prefix), value
        yield from _walk_dependency_tables(value, next_prefix)


def check_f2_feature_boundaries(root: pathlib.Path) -> CheckResult:
    """Require crash/fault injection to stay off defaults and dev-only."""

    findings: list[Finding] = []
    try:
        manifests = _workspace_manifests(root)
    except ValueError as error:
        return CheckResult(
            "F2 failpoints/fault injection remain dev-only",
            (Finding("Cargo.toml", 0, str(error)),),
        )
    laboratory_features = {"failpoints", "relay-fault-injection"}
    for manifest in manifests:
        relative = manifest.relative_to(root).as_posix()
        try:
            document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            findings.append(Finding(relative, 0, f"cannot parse manifest: {error}"))
            continue
        defaults = document.get("features", {}).get("default", [])
        if isinstance(defaults, list):
            leaked = laboratory_features.intersection(defaults)
            for feature in sorted(leaked):
                findings.append(Finding(relative, 0, f"{feature} is a default feature"))
        features = document.get("features", {})
        if isinstance(features, dict):
            for feature_name, activations in features.items():
                if not isinstance(activations, list):
                    continue
                for activation in activations:
                    if not isinstance(activation, str):
                        continue
                    dependency_feature = activation.rsplit("/", maxsplit=1)[-1]
                    if dependency_feature in laboratory_features:
                        findings.append(
                            Finding(
                                relative,
                                0,
                                f"feature {feature_name} forwards laboratory feature {activation}",
                            )
                        )
        for table_name, dependencies in _walk_dependency_tables(document):
            is_dev = table_name.endswith("dev-dependencies")
            for dependency, value in dependencies.items():
                if not isinstance(value, dict):
                    continue
                enabled = value.get("features", [])
                if not isinstance(enabled, list):
                    continue
                for feature in sorted(laboratory_features.intersection(enabled)):
                    if not is_dev:
                        findings.append(
                            Finding(
                                relative,
                                0,
                                f"{dependency} enables {feature} from {table_name}, not dev-dependencies",
                            )
                        )
    return CheckResult("F2 failpoints/fault injection remain dev-only", tuple(findings))


def check_store_never_extracts_adaptor_secret(root: pathlib.Path) -> CheckResult:
    """Keep the adaptor scalar out of the Store, in product and in tests alike."""

    name = "Store never extracts the adaptor secret"
    findings: list[Finding] = []
    forbidden = ("extract_revealed_secret_be_bytes", "verify_and_extract")
    source_root = root / "crates" / "dom-scriptless-store" / "src"
    for path in sorted(source_root.rglob("*.rs")):
        source = path.read_text(encoding="utf-8")
        # Comments and string literals are masked so prose about the rule is not
        # itself a violation.  Test-only items are deliberately NOT masked: the
        # Store must not reach the scalar in any build, and a test would be the
        # first place the capability reappeared.  The only permitted proof is
        # verify_final_signature_opens_adaptor_point_v1, which returns unit and
        # drops the zeroizing secret inside dom-adaptor.
        code = sanitize_source(source, strip_strings=True)
        relative = path.relative_to(root).as_posix()
        for symbol in forbidden:
            for match in re.finditer(rf"\b{re.escape(symbol)}\b", code):
                findings.append(
                    Finding(
                        relative,
                        _line_at(code, match.start()),
                        f"Store reaches the adaptor scalar through {symbol}; the only "
                        "permitted proof is verify_final_signature_opens_adaptor_point_v1, "
                        "which returns unit and drops the zeroizing secret",
                    )
                )
    return CheckResult(name, tuple(findings))


_STORE_CUSTODY_TRAITS = frozenset(
    {
        # Custody of secret material.
        "SharedBlindingVaultV1",
        "RestartableSharedBlindingVaultV1",
        "CollaborativeBpNonceVaultV1",
        "NonceVaultV1",
        "RestartArtifactRecoveryVaultV1",
        # Authority to authorize or to sink a transaction.
        "OperationalFundingAuthorizationStoreV1",
        "OperationalM8FundingAuthorizationStoreV1",
        "OperationalM8FundingAuthorizationStoreV2",
        "OperationalFundingTransactionSinkV1",
        "OperationalM8FundingTransactionSinkV1",
        "OperationalM8FundingTransactionSinkV2",
        "OperationalClaimTransactionSinkV1",
        # Custody of a reservation lookup and of a signing session.
        "ReservationLookupCustodyV1",
        "ReservationLookupRecoveryCustodyV1",
        "DurableReservationLookupV1",
        "SigningSessionAuthorityV1",
        "OperationalSigningSessionAuthorityV1",
        "AcceptedSigningSessionV1",
        "AcceptedOperationalSigningSessionV1",
    }
)

# Every implementation of a custody trait that the Store ships today, pinned
# pair by pair.  This list is the decision record: adding an entry is the act
# of deciding that a new type may hold custody outside `cfg(test)`, and it is
# meant to be argued for in review rather than appended to in passing.
_STORE_CUSTODY_IMPLEMENTATIONS = frozenset(
    {
        ("AcceptedOperationalSigningSessionV1", "AcceptedContractsSigningSessionV1"),
        ("AcceptedSigningSessionV1", "AcceptedContractsSigningSessionV1"),
        ("CollaborativeBpNonceVaultV1", "ContractsNonceVaultV1"),
        ("DurableReservationLookupV1", "DurableContractsReservationLookupV1"),
        ("NonceVaultV1", "ContractsNonceVaultV1"),
        ("OperationalClaimTransactionSinkV1", "FinalClaimTransactionSinkRefV2"),
        ("OperationalFundingAuthorizationStoreV1", "ContractsSessionStoreV1"),
        ("OperationalFundingAuthorizationStoreV1", "FundingAuthorizationRefV1"),
        ("OperationalFundingTransactionSinkV1", "ContractsSessionStoreV1"),
        ("OperationalFundingTransactionSinkV1", "FundingTransactionSinkRefV1"),
        ("OperationalM8FundingAuthorizationStoreV1", "ContractsSessionStoreV1"),
        ("OperationalM8FundingAuthorizationStoreV1", "M8FundingAuthorizationRefV1"),
        ("OperationalM8FundingAuthorizationStoreV2", "M8FundingAuthorizationRefV2"),
        ("OperationalM8FundingTransactionSinkV1", "ContractsSessionStoreV1"),
        ("OperationalM8FundingTransactionSinkV1", "M8FundingTransactionSinkRefV1"),
        ("OperationalM8FundingTransactionSinkV2", "M8FundingTransactionSinkRefV2"),
        ("OperationalSigningSessionAuthorityV1", "ContractsSigningSessionAuthorityV1"),
        ("ReservationLookupCustodyV1", "ContractsReservationLookupCustodyV1"),
        ("ReservationLookupRecoveryCustodyV1", "ContractsReservationLookupCustodyV1"),
        ("RestartArtifactRecoveryVaultV1", "ContractsNonceVaultV1"),
        ("RestartableSharedBlindingVaultV1", "ContractsNonceVaultV1"),
        ("SharedBlindingVaultV1", "ContractsNonceVaultV1"),
    }
)

_STORE_CUSTODY_IMPL = re.compile(
    r"\bimpl(?:\s*<[^>]*>)?\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*<[^>]*>)?\s+for\s+([A-Za-z_][A-Za-z0-9_]*)"
)


def check_store_custody_traits_stay_out_of_the_laboratory(
    root: pathlib.Path,
    *,
    _sources: tuple[RustSource, ...] | None = None,
    _source_error: str | None = None,
) -> CheckResult:
    """Keep test doubles for custody traits out of the `evidence-only` surface.

    `check_evidence_only_isolation` is a manifest check: it proves the
    laboratory surface is unreachable from any shipped feature and from any
    normal dependency table.  It never reads Rust, so it says nothing about
    what the surface *contains* -- a vault that keeps the share in plaintext
    and seals nothing passes every one of its rules.  `compile_error!` in
    `dom-scriptless-store/src/lib.rs` does not close the gap either: it fires
    on `not(debug_assertions)`, and the laboratory surface lives precisely in
    the debug builds of whoever depends on the crate.

    **This guard cannot tell a double from a real implementation**, and no
    source analysis can: both are a struct with the trait's methods.  So it
    decides the question it can decide.  Every implementation of a custody
    trait that survives the test-only masking is compared against a pinned
    inventory of the ones the Store ships today.  An unpinned pair is a
    finding -- whether it is a genuine new implementation or a fixture that
    escaped `mod tests` under `#[cfg(any(test, feature = "evidence-only"))]`,
    it is a custody decision, and a custody decision is not something a patch
    makes on its way past.

    The masking is what gives the rule its edge: `cfg_implies_test` holds for
    `#[cfg(test)]` and does **not** hold for
    `#[cfg(any(test, feature = "evidence-only"))]`, so a double stays invisible
    while it is test-only and becomes a finding the moment the feature can
    reach it.  That is the exact transition this guard exists to refuse.
    """

    name = "Store custody traits are implemented only by pinned product types"
    findings: list[Finding] = []
    if _source_error is not None:
        return CheckResult(name, (Finding("Cargo.toml", 0, _source_error),))
    if _sources is None:
        try:
            sources = load_rust_sources(root)
        except ValueError as error:
            return CheckResult(name, (Finding("Cargo.toml", 0, str(error)),))
    else:
        sources = _sources
    prefix = "crates/dom-scriptless-store/src/"
    for source in sources:
        if not source.relative_path.startswith(prefix):
            continue
        for match in _STORE_CUSTODY_IMPL.finditer(source.code):
            trait, implementor = match.group(1), match.group(2)
            if trait not in _STORE_CUSTODY_TRAITS:
                continue
            if (trait, implementor) in _STORE_CUSTODY_IMPLEMENTATIONS:
                continue
            findings.append(
                Finding(
                    source.relative_path,
                    _line_at(source.code, match.start()),
                    f"{implementor} implements the custody trait {trait} in code "
                    "the evidence-only feature can reach; a test double belongs "
                    "under cfg(test) alone, and a real implementation belongs in "
                    "_STORE_CUSTODY_IMPLEMENTATIONS with the decision recorded",
                )
            )
    return CheckResult(name, tuple(findings))


def check_evidence_only_isolation(root: pathlib.Path) -> CheckResult:
    """Keep the Store `evidence-only` surface out of every shipped feature graph."""

    name = "evidence-only Store surface is never a normal dependency or shipped feature"
    findings: list[Finding] = []
    try:
        manifests = _guarded_manifests(root)
    except ValueError as error:
        return CheckResult(name, (Finding("Cargo.toml", 0, str(error)),))
    shipped = ("default", "production", "development", "simulation")
    for manifest in manifests:
        relative = manifest.relative_to(root).as_posix()
        try:
            document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            findings.append(Finding(relative, 0, f"cannot parse manifest: {error}"))
            continue
        features = document.get("features", {})
        if not isinstance(features, dict):
            features = {}
        # Any feature that forwards `<dep>/evidence-only` (weak `?` form included)
        # must itself carry `evidence-only` in its name, so the laboratory
        # surface can never hide behind a neutral feature name.
        for feature_name, activations in features.items():
            if not isinstance(activations, list):
                continue
            for activation in activations:
                if not isinstance(activation, str):
                    continue
                forwarded = activation.rsplit("/", maxsplit=1)[-1]
                if forwarded == "evidence-only" and "evidence-only" not in feature_name:
                    findings.append(
                        Finding(
                            relative,
                            0,
                            f"feature {feature_name} forwards {activation} under a neutral name",
                        )
                    )
        # Transitive closure of every shipped feature inside this manifest.
        # The walk only follows local activations; cross-crate forwarding is
        # closed at the source by rule (a) above (a forwarding feature must carry
        # `evidence-only` in its own name, so the consumer's activation string
        # is caught here by substring).  Do not relax rule (a) as cosmetic.
        for entry in shipped:
            seen: set[str] = set()
            pending = [entry]
            while pending:
                current = pending.pop()
                if current in seen:
                    continue
                seen.add(current)
                for activation in features.get(current, []) or []:
                    if not isinstance(activation, str):
                        continue
                    if "evidence-only" in activation:
                        findings.append(
                            Finding(
                                relative,
                                0,
                                f"shipped feature {entry} reaches {activation} via {current}",
                            )
                        )
                    if "/" not in activation and not activation.startswith("dep:"):
                        pending.append(activation)
        # Only dev-dependencies may enable `evidence-only` on a dependency.
        for table_name, dependencies in _walk_dependency_tables(document):
            if table_name.endswith("dev-dependencies"):
                continue
            for dependency, value in dependencies.items():
                if not isinstance(value, dict):
                    continue
                enabled = value.get("features", [])
                # Substring, not equality: rule (a) legitimately mints names such as
                # `evidence-only-ancestry-tests`, and enabling any of them from a
                # normal dependency table would still pull the laboratory surface in.
                if isinstance(enabled, list) and any(
                    isinstance(feature, str) and "evidence-only" in feature
                    for feature in enabled
                ):
                    findings.append(
                        Finding(
                            relative,
                            0,
                            f"{dependency} enables evidence-only from {table_name}, not dev-dependencies",
                        )
                    )
    return CheckResult(name, tuple(findings))


def check_f5_c1a_boundary(
    root: pathlib.Path,
    *,
    _sources: tuple[RustSource, ...] | None = None,
    _source_error: str | None = None,
) -> CheckResult:
    """Keep the BIP327 C1a conformance translation unit out of product code."""

    findings: list[Finding] = []
    try:
        manifests = _guarded_manifests(root)[1:]
    except ValueError as error:
        findings.append(Finding("Cargo.toml", 0, str(error)))
        manifests = ()
    for manifest in manifests:
        relative = manifest.relative_to(root).as_posix()
        if relative == "crates/adapters/btc-secp-c1a/Cargo.toml":
            continue
        try:
            document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            findings.append(Finding(relative, 0, f"cannot parse manifest: {error}"))
            continue
        for table_name, dependencies in _walk_dependency_tables(document):
            if table_name.endswith("dev-dependencies"):
                continue
            for alias, value in dependencies.items():
                package = value.get("package", alias) if isinstance(value, dict) else alias
                if package == "btc-secp-c1a":
                    findings.append(
                        Finding(
                            relative,
                            0,
                            f"btc-secp-c1a (alias {alias}) is enabled from {table_name}",
                        )
                    )

    if _source_error is not None:
        findings.append(Finding("Cargo.toml", 0, _source_error))
    else:
        if _sources is None:
            try:
                sources = load_rust_sources(root)
            except ValueError as error:
                findings.append(Finding("Cargo.toml", 0, str(error)))
                sources = ()
        else:
            sources = _sources
        for source in sources:
            if source.relative_path.startswith("crates/adapters/btc-secp-c1a/"):
                continue
            for number, code in enumerate(source.code_lines, start=1):
                if re.search(r"\bbtc_secp_c1a\s*::", code):
                    findings.append(
                        Finding(source.relative_path, number, "product imports btc-secp-c1a")
                    )
    return CheckResult("F5 C1a stays a dev-only conformance harness", tuple(findings))


def check_f5_evidence_boundary(root: pathlib.Path) -> CheckResult:
    """Keep btc-evidence verify-only and free of signing/custody dependencies."""

    findings: list[Finding] = []
    crate = root / "crates" / "adapters" / "btc-evidence"
    manifest = crate / "Cargo.toml"
    dangerous_dependencies = {
        "adapter-btc",
        "btc-actuator",
        "btc-crypto",
        "btc-live",
        "btc-vault",
        "dom-adaptor",
        "dom-wallet",
        "evm-actuator",
    }
    try:
        document = tomllib.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        findings.append(Finding(manifest.relative_to(root).as_posix(), 0, f"cannot parse: {error}"))
    else:
        for table_name, dependencies in _walk_dependency_tables(document):
            if table_name.endswith("dev-dependencies"):
                continue
            for alias, value in dependencies.items():
                package = value.get("package", alias) if isinstance(value, dict) else alias
                if package in dangerous_dependencies:
                    findings.append(
                        Finding(
                            manifest.relative_to(root).as_posix(),
                            0,
                            f"custody/signing dependency {package} (alias {alias}) from {table_name}",
                        )
                    )

    forbidden_function = re.compile(
        r"\bfn\s+(?:sign|fund|adapt|set_?nonce|custod|export_share|partial_sign|broadcast|sendraw)"
        r"[A-Za-z0-9_]*\s*\(",
        re.IGNORECASE,
    )
    source_root = crate / "src"
    if not source_root.is_dir():
        findings.append(Finding("crates/adapters/btc-evidence/src", 0, "source directory absent"))
    else:
        for path in sorted(source_root.rglob("*.rs")):
            source = path.read_text(encoding="utf-8")
            code = mask_test_only_items(sanitize_source(source, strip_strings=True))
            for match in forbidden_function.finditer(code):
                findings.append(
                    Finding(
                        path.relative_to(root).as_posix(),
                        _line_at(code, match.start()),
                        f"evidence module owns forbidden operation: {match.group(0).strip()}",
                    )
                )
    return CheckResult("F5 btc-evidence remains verify-only", tuple(findings))


def _normalize_automation_text(value: str) -> str:
    replacements = {
        '"$script_dir/': "scripts/",
        "'$script_dir/": "scripts/",
        "${script_dir}/": "scripts/",
        "$script_dir/": "scripts/",
        '"$repo/': "",
        "'$repo/": "",
        "${repo}/": "",
        "$repo/": "",
        '"$REPO_ROOT/': "",
        "'$REPO_ROOT/": "",
        "${REPO_ROOT}/": "",
        "$REPO_ROOT/": "",
        "${GITHUB_WORKSPACE}/": "",
        "$GITHUB_WORKSPACE/": "",
    }
    for prefix, replacement in replacements.items():
        value = value.replace(prefix, replacement)
    return value


def _literal_process_arguments(node: ast.AST) -> tuple[str, ...] | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value,)
    if isinstance(node, (ast.List, ast.Tuple)):
        values: list[str] = []
        for element in node.elts:
            if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
                return None
            values.append(element.value)
        return tuple(values)
    return None


def _python_process_commands(path: pathlib.Path, source: str) -> tuple[list[str], list[str]]:
    """Return literal process command text and fail-closed parser errors."""

    commands: list[str] = []
    errors: list[str] = []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as error:
        return [], [f"cannot parse reachable Python automation: {error}"]
    process_modules: dict[str, str] = {
        "os": "os",
        "subprocess": "subprocess",
        "asyncio": "asyncio",
    }
    direct_calls: dict[str, str] = {}
    process_attributes = {
        "os": {
            "system",
            "popen",
            "execv",
            "execve",
            "execl",
            "execlp",
            "execvp",
            "execvpe",
            "spawnl",
            "spawnle",
            "spawnlp",
            "spawnlpe",
            "spawnv",
            "spawnve",
            "spawnvp",
            "spawnvpe",
        },
        "subprocess": {"call", "check_call", "check_output", "Popen", "run"},
        "asyncio": {"create_subprocess_exec", "create_subprocess_shell"},
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in process_attributes:
                    process_modules[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in process_attributes:
            for alias in node.names:
                if alias.name == "*":
                    errors.append(f"wildcard process import at line {node.lineno}")
                elif alias.name in process_attributes[node.module]:
                    direct_calls[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                if not isinstance(target, ast.Name) or value is None:
                    continue
                if isinstance(value, ast.Name) and value.id in process_modules:
                    process_modules[target.id] = process_modules[value.id]
                elif isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
                    module = process_modules.get(value.value.id)
                    if module is not None and value.attr in process_attributes[module]:
                        direct_calls[target.id] = f"{module}.{value.attr}"

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = process_modules.get(node.func.value.id)
            name = f"{module}.{node.func.attr}" if module is not None else ""
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
            nested = node.func.value
            if isinstance(nested.func, ast.Name) and nested.func.id in {"getattr", "__import__"}:
                errors.append(f"dynamic process lookup at line {node.lineno}")
            name = ""
        elif isinstance(node.func, ast.Name):
            name = direct_calls.get(node.func.id, "")
        else:
            name = ""
        if isinstance(node.func, ast.Call) and isinstance(node.func.func, ast.Name):
            if node.func.func.id in {"getattr", "__import__"}:
                errors.append(f"dynamic process lookup at line {node.lineno}")
        if isinstance(node.func, ast.Name) and node.func.id == "__import__" and node.args:
            imported = _literal_process_arguments(node.args[0])
            if imported is None or any(value in process_attributes for value in imported):
                errors.append(f"dynamic process import at line {node.lineno}")
        if not name:
            continue
        module, attribute = name.split(".", maxsplit=1)
        if attribute not in process_attributes[module]:
            continue
        if not node.args:
            errors.append(f"dynamic process dispatch at line {node.lineno}")
            continue
        argument_node = node.args[0]
        if module == "os" and attribute.startswith(("exec", "spawn")) and len(node.args) > 1:
            argument_node = node.args[1]
        arguments = _literal_process_arguments(argument_node)
        if arguments is None:
            errors.append(f"dynamic process dispatch at line {node.lineno}")
        else:
            commands.append(" ".join(arguments))
    return commands, errors


def _automation_roots(root: pathlib.Path) -> tuple[pathlib.Path, ...]:
    candidates: set[pathlib.Path] = {root / "scripts" / "ci_local.sh"}
    workflows = root / ".github" / "workflows"
    actions = root / ".github" / "actions"
    if workflows.is_dir():
        candidates.update(workflows.rglob("*.yml"))
        candidates.update(workflows.rglob("*.yaml"))
    if actions.is_dir():
        candidates.update(actions.rglob("action.yml"))
        candidates.update(actions.rglob("action.yaml"))
    for name in ("Makefile", "makefile", "GNUmakefile"):
        candidate = root / name
        if candidate.exists() or candidate.is_symlink():
            candidates.add(candidate)
    return tuple(sorted(path for path in candidates if path.exists() or path.is_symlink()))


def _automation_candidates(
    root: pathlib.Path, current: pathlib.Path, raw: str
) -> tuple[pathlib.Path, ...]:
    """Resolve a literal wrapper path both from repository and file context."""

    cleaned = raw.rstrip(".,:;\"'")
    pure = pathlib.PurePosixPath(cleaned)
    if pure.is_absolute():
        return ()
    if pure.parts and pure.parts[0] in {"scripts", "contracts", ".github"}:
        values = (root / pathlib.Path(*pure.parts),)
    else:
        values = (
            root / pathlib.Path(*pure.parts),
            current.parent / pathlib.Path(*pure.parts),
        )
    return tuple(dict.fromkeys(values))


def _is_automation_file(path: pathlib.Path, root: pathlib.Path) -> bool:
    suffixes = {".sh", ".bash", ".py", ".yml", ".yaml", ".mk"}
    if path.suffix in suffixes or path.name in {"Makefile", "makefile", "GNUmakefile"}:
        return True
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    return (
        relative.parts
        and relative.parts[0] in {"scripts", "contracts", ".github"}
        and path.is_file()
        and bool(path.stat().st_mode & 0o111)
    )


def check_f5_signet_automation(root: pathlib.Path) -> CheckResult:
    """Reject any literal or unresolved route from automation to live Signet."""

    findings: list[Finding] = []
    root_resolved = root.resolve(strict=True)
    pending = list(_automation_roots(root))
    visited: set[pathlib.Path] = set()
    while pending:
        path = pending.pop()
        relative_hint = path.relative_to(root).as_posix()
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root_resolved)
        except (OSError, ValueError) as error:
            findings.append(Finding(relative_hint, 0, f"automation path escapes or is absent: {error}"))
            continue
        if path.is_symlink() or not path.is_file():
            findings.append(Finding(relative_hint, 0, "automation entry is not a regular in-tree file"))
            continue
        if resolved in visited:
            continue
        visited.add(resolved)
        relative = resolved.relative_to(root_resolved).as_posix()
        try:
            source = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            findings.append(Finding(relative, 0, f"cannot read automation entry: {error}"))
            continue

        command_sources: list[str]
        if resolved.suffix == ".py":
            command_sources, errors = _python_process_commands(resolved, source)
            findings.extend(Finding(relative, 0, message) for message in errors)
        else:
            # Full-line comments cannot execute.  Everything else is parsed
            # conservatively, including YAML run blocks and Make recipes.
            executable = "\n".join(
                "" if line.lstrip().startswith("#") else line for line in source.splitlines()
            )
            command_sources = [executable]

        for command_source in command_sources:
            normalized = _normalize_automation_text(command_source)
            dequoted = normalized.replace('"', "").replace("'", "")
            for scanned in (command_source, normalized, dequoted):
                for pattern in _DYNAMIC_REPOSITORY_DISPATCH:
                    if match := pattern.search(scanned):
                        findings.append(
                            Finding(
                                relative,
                                _line_at(scanned, match.start()),
                                "dynamic repository automation dispatch is forbidden",
                            )
                        )
                for match in _LIVE_SIGNET_COMMAND.finditer(scanned):
                    findings.append(
                        Finding(
                            relative,
                            _line_at(scanned, match.start()),
                            "live Signet command is reachable from automation",
                        )
                    )
                if match := _SIGNET_AUTOMATION_TOKEN.search(scanned):
                    findings.append(
                        Finding(
                            relative,
                            _line_at(scanned, match.start()),
                            "Signet token is reachable from executable automation",
                        )
                    )
            for match in _AUTOMATION_PATH.finditer(dequoted):
                raw = match.group("path").rstrip(".,")
                for candidate in _automation_candidates(root, resolved, raw):
                    try:
                        lexical = candidate.resolve(strict=False).relative_to(root_resolved)
                    except ValueError:
                        continue
                    canonical = lexical.as_posix()
                    if canonical in MANUAL_SIGNET_RUNNERS:
                        findings.append(
                            Finding(
                                relative,
                                _line_at(dequoted, match.start()),
                                "manual Signet runner is automation-reachable",
                            )
                        )
                        continue
                    if candidate.is_dir():
                        manifests = [candidate / "action.yml", candidate / "action.yaml"]
                        pending.extend(
                            item for item in manifests if item.exists() or item.is_symlink()
                        )
                    elif (candidate.exists() or candidate.is_symlink()) and _is_automation_file(
                        candidate, root
                    ):
                        pending.append(candidate)

    return CheckResult("F5 Signet automation closure", tuple(sorted(set(findings))))


def _strict_json(path: pathlib.Path) -> object:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)


def _require_static(condition: bool, message: str) -> None:
    """Fail a static policy check even when Python assertions are optimized out."""

    if not condition:
        raise ValueError(message)


def _parse_unique_config(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{path.name}:{number}: malformed config line")
        key, value = (part.strip() for part in line.split("=", maxsplit=1))
        if not key or key in values:
            raise ValueError(f"{path.name}:{number}: duplicate or empty config key {key!r}")
        values[key] = value
    return values


def _script_refuses_dirty_or_tracked_signer(source: str) -> bool:
    """Require explicit, unconditional refusal blocks in the manual runner."""

    strict = re.search(r"(?m)^set\s+-[^\n]*e[^\n]*u[^\n]*pipefail\s*$", source) is not None

    def refusing_block(command: str) -> bool:
        return (
            re.search(
                rf"(?m)^[ \t]*if[ \t]+{command}[ \t]*;?[ \t]*then[ \t]*"
                rf"(?:\r?\n[ \t]*)?exit[ \t]+[1-9][0-9]*[ \t]*;?[ \t]*"
                rf"(?:\r?\n[ \t]*)?fi[ \t]*$",
                source,
            )
            is not None
        )

    dirty = refusing_block(r"!\s+git\s+diff\s+--quiet\s+--")
    cached = refusing_block(r"!\s+git\s+diff\s+--cached\s+--quiet\s+--")
    signer = refusing_block(
        r"git\s+ls-files\s+--error-unmatch\s+--\s+[^;\r\n]*(?:signer|signing)[^;\r\n]*\.wif"
    )
    reenabled = re.search(r"(?m)^[ \t]*set\s+\+[^\r\n]*(?:e|u)", source) is not None
    git_override = re.search(
        r"(?m)^[ \t]*(?:function[ \t]+git\b|git[ \t]*\(\s*\))", source
    ) is not None
    return strict and dirty and cached and signer and not reenabled and not git_override


def check_f5_signet_static(root: pathlib.Path) -> CheckResult:
    """Keep Signet disabled; statically validate a future complete bundle."""

    findings: list[Finding] = list(check_f5_signet_automation(root).findings)
    required = (
        root / "scripts" / "f5-signet-custom-e2e.sh",
        root / "scripts" / "f5-signet-public-e2e.sh",
        root / "infra" / "signet" / "network.json",
        root / "infra" / "signet" / "conformance-terms.json",
        root / "infra" / "signet" / "miner.conf",
        root / "infra" / "signet" / "observer.conf",
    )
    present = [path for path in required if path.exists() or path.is_symlink()]
    if present and len(present) != len(required):
        missing = [
            path.relative_to(root).as_posix()
            for path in required
            if not path.exists() and not path.is_symlink()
        ]
        findings.append(Finding("infra/signet", 0, "partial Signet bundle: " + ", ".join(missing)))
    elif len(present) == len(required):
        irregular = [
            path.relative_to(root).as_posix()
            for path in required
            if path.is_symlink() or not path.is_file()
        ]
        if irregular:
            findings.append(
                Finding(
                    "infra/signet",
                    0,
                    "Signet bundle must contain regular in-tree files: "
                    + ", ".join(irregular),
                )
            )
            return CheckResult(
                "F5 Signet policy is static-only and disabled",
                tuple(findings),
                "execution disabled; malformed bundle refused",
            )
        try:
            network = _strict_json(required[2])
            terms = _strict_json(required[3])
            _require_static(
                isinstance(network, dict) and isinstance(terms, dict),
                "network and terms roots must be objects",
            )
            core = network["bitcoin_core"]
            policy = network["policy"]
            topology = network["topology"]
            network_values = network["network"]
            csv = terms["csv_profile"]
            _require_static(isinstance(core, dict), "bitcoin_core must be an object")
            _require_static(isinstance(policy, dict), "policy must be an object")
            _require_static(isinstance(topology, dict), "topology must be an object")
            _require_static(isinstance(network_values, dict), "network must be an object")
            _require_static(isinstance(csv, dict), "csv_profile must be an object")
            _require_static(
                network["schema"] == "dom-interop/f5-custom-signet-network/v1",
                "unexpected network schema",
            )
            _require_static(
                terms["schema"] == "dom-interop/f5-custom-signet-conformance-terms/v1",
                "unexpected terms schema",
            )
            _require_static(
                terms["network_identity"] == "infra/signet/network.json",
                "terms do not bind the network file",
            )
            _require_static(
                terms["network_kind"] == "custom-signet-bip325",
                "unexpected terms network kind",
            )
            _require_static(core["version"] == "31.0.0", "Bitcoin Core version drift")
            for name in ("binary_sha256", "source_sha256", "official_signet_miner_sha256"):
                _require_static(
                    re.fullmatch(r"[0-9a-f]{64}", str(core[name])) is not None,
                    f"invalid {name}",
                )
            challenge = bytes.fromhex(str(network_values["challenge"]))
            _require_static(
                network_values["challenge_type"] == "p2pk-1-of-1",
                "challenge must be non-trivial P2PK 1-of-1",
            )
            _require_static(
                len(challenge) == 35
                and challenge[0] == 33
                and challenge[1] in {2, 3}
                and challenge[-1] == 0xAC,
                "challenge is not canonical compressed-key P2PK",
            )
            _require_static(
                challenge.hex() == CUSTOM_SIGNET_CHALLENGE_HEX,
                "custom Signet challenge drift",
            )
            _require_static(
                hashlib.sha256(challenge).hexdigest()
                == network_values["challenge_hash_sha256"],
                "challenge hash mismatch",
            )
            magic = hashlib.sha256(
                hashlib.sha256(bytes([len(challenge)]) + challenge).digest()
            ).digest()[:4]
            _require_static(magic.hex() == network_values["message_magic"], "magic mismatch")
            _require_static(
                topology["miner"]["rpc"] != topology["observer"]["rpc"],
                "miner and observer RPC endpoints overlap",
            )
            _require_static(
                topology["miner"]["p2p"] != topology["observer"]["p2p"],
                "miner and observer P2P endpoints overlap",
            )
            _require_static(
                topology["miner"]["config"] == "infra/signet/miner.conf",
                "miner config path drift",
            )
            _require_static(
                topology["observer"]["config"] == "infra/signet/observer.conf",
                "observer config path drift",
            )
            _require_static(
                topology["miner"]["rpc"] == "127.0.0.1:39443"
                and topology["miner"]["p2p"] == "127.0.0.1:39444"
                and topology["observer"]["rpc"] == "127.0.0.1:39453"
                and topology["observer"]["p2p"] == "127.0.0.1:39454",
                "Signet topology is not the frozen loopback topology",
            )
            _require_static(policy["public_signet_required"] is False, "public network enabled")
            _require_static(policy["mainnet_allowed"] is False, "mainnet enabled")
            _require_static(policy["minimum_confirmations"] == 2, "confirmation policy drift")
            _require_static(policy["conformance_csv_blocks"] == 17, "conformance CSV drift")
            _require_static(policy["production_csv_blocks"] == 144, "production CSV drift")
            _require_static(policy["mempool_persistence"] is False, "mempool persistence enabled")
            _require_static(policy["wallet_rebroadcast"] is False, "wallet rebroadcast enabled")
            _require_static(csv["scope"] == "conformance-only", "CSV scope is not conformance-only")
            _require_static(csv["blocks"] == 17, "terms conformance CSV drift")
            _require_static(csv["production_blocks"] == 144, "terms production CSV drift")
            _require_static(csv["production_profile_changed"] is False, "production profile changed")
            _require_static(
                terms["finality_policy"]["minimum_confirmations"] == 2,
                "terms confirmation policy drift",
            )
            _require_static(
                terms["finality_policy"]["reorg_rows_require_reconfirmation"] is True,
                "reorg reconfirmation disabled",
            )
            rows = terms["rows"]
            _require_static(
                isinstance(rows, dict)
                and set(rows) == {f"E{index:02d}" for index in range(1, 17)},
                "conformance row set drift",
            )
        except (KeyError, OSError, TypeError, ValueError) as error:
            findings.append(Finding("infra/signet", 0, f"invalid static Signet bundle: {error}"))

        combined = "\n".join(path.read_text(encoding="utf-8") for path in required[:2])
        configs = "\n".join(path.read_text(encoding="utf-8") for path in required[4:])
        if re.search(
            r"^[ \t]*(?:rpcuser|rpcpassword|rpcauth)[ \t]*=", configs, re.MULTILINE
        ):
            findings.append(Finding("infra/signet", 0, "static RPC credentials are forbidden"))
        if re.search(r"OP_TRUE|generateblock|generatetoaddress", combined + configs, re.IGNORECASE):
            findings.append(Finding("infra/signet", 0, "trivial challenge/mining RPC is forbidden"))
        if re.search(r"minimum_confirmations\s*[-+]\s*1|minimum_confirmations\s*\)\s*-\s*1", combined):
            findings.append(Finding("scripts", 0, "confirmation depth must include the block"))
        custom = required[0].read_text(encoding="utf-8")
        if not _script_refuses_dirty_or_tracked_signer(custom):
            findings.append(
                Finding(
                    required[0].relative_to(root).as_posix(),
                    0,
                    "runner lacks fail-closed dirty-tree/tracked-signer control flow",
                )
            )
        try:
            miner_config = _parse_unique_config(required[4])
            observer_config = _parse_unique_config(required[5])
            common_config = {
                "signet": "1",
                "signetchallenge": CUSTOM_SIGNET_CHALLENGE_HEX,
                "server": "1",
                "rpcbind": "127.0.0.1",
                "rpcallowip": "127.0.0.1",
                "persistmempool": "0",
                "walletbroadcast": "0",
                "dnsseed": "0",
                "listenonion": "0",
            }
            for label, config in (("miner", miner_config), ("observer", observer_config)):
                for key, value in common_config.items():
                    _require_static(
                        config.get(key) == value,
                        f"{label} config requires {key}={value}",
                    )
            for label, config, rpc_port, p2p_port, peer in (
                ("miner", miner_config, "39443", "39444", "127.0.0.1:39454"),
                ("observer", observer_config, "39453", "39454", "127.0.0.1:39444"),
            ):
                _require_static(
                    config.get("rpcport") == rpc_port
                    and config.get("port") == p2p_port
                    and config.get("connect") == peer,
                    f"{label} config does not match frozen loopback ports/peer",
                )
        except (OSError, UnicodeError, ValueError) as error:
            findings.append(Finding("infra/signet", 0, f"invalid Signet config: {error}"))

    note = (
        "execution disabled; support bundle absent"
        if not present
        else "execution disabled; structure checked (declared binary digests are not provenance proof)"
    )
    return CheckResult("F5 Signet policy is static-only and disabled", tuple(findings), note)


def check_f1_secp_contexts(root: pathlib.Path) -> CheckResult:
    """Require syntactically bound fresh-entropy randomization in btc-live."""

    findings: list[Finding] = []
    source_root = root / "crates" / "adapters" / "btc-live" / "src"
    # Emptied 2026-09-02: the one inventoried literal context,
    # `SecpContext::new(&[0x5a; 32])` in `fresh.rs`, now sits inside a
    # `#[cfg(test)]` impl and is masked, so production btc-live builds every
    # context from `fresh_entropy()`.  Any new literal is a finding.
    literal_expected: collections.Counter[tuple[str, str]] = collections.Counter()
    literal_actual: collections.Counter[tuple[str, str]] = collections.Counter()
    for path in sorted(source_root.rglob("*.rs")):
        source = path.read_text(encoding="utf-8")
        code = mask_test_only_items(sanitize_source(source, strip_strings=True))
        lines = code.splitlines()
        originals = source.splitlines()
        relative = path.relative_to(root).as_posix()
        assignments: list[tuple[int, int]] = []
        assignment_pattern = re.compile(
            r"\blet\s+mut\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*Secp256k1::new\s*\(\s*\)\s*;"
        )
        for assignment in assignment_pattern.finditer(code):
            variable = assignment.group(1)
            number = _line_at(code, assignment.start())
            assignments.append((assignment.start(), assignment.end()))
            randomize = re.match(
                rf"\s*{re.escape(variable)}\.seeded_randomize\s*\((?P<argument>.*?)\)\s*;",
                code[assignment.end() :],
                re.DOTALL,
            )
            if randomize is None:
                findings.append(
                    Finding(relative, number, "Secp256k1 context is used before seeded_randomize")
                )
            elif re.search(r"\bfresh_entropy\s*\(", randomize.group("argument")) is None:
                findings.append(
                    Finding(relative, number, "seeded_randomize lacks fresh_entropy provenance")
                )

        for constructor in re.finditer(r"\bSecp256k1::new\s*\(\s*\)", code):
            if not any(start <= constructor.start() < end for start, end in assignments):
                findings.append(
                    Finding(
                        relative,
                        _line_at(code, constructor.start()),
                        "unbound Secp256k1::new() in production",
                    )
                )
        if re.search(r"\buse\b[^;\n]*\b(?:Secp256k1|SecpContext)\b[^;\n]*\bas\b", code) \
                or re.search(
                    r"\btype\s+[A-Za-z_][A-Za-z0-9_]*[^=;\n]*=\s*[^;\n]*"
                    r"\b(?:Secp256k1|SecpContext)\b",
                    code,
                ):
            findings.append(Finding(relative, 0, "secp context aliases are forbidden in btc-live"))
        for default in re.finditer(
            r"\b(?:Secp256k1|SecpContext)\s*::\s*default\s*\(\s*\)", code
        ):
            findings.append(
                Finding(
                    relative,
                    _line_at(code, default.start()),
                    "default secp context constructor is forbidden in production",
                )
            )

        for number, line in enumerate(lines, start=1):
            if re.search(r"SecpContext::new\s*\(\s*&\s*\[", line):
                literal_actual[(relative, originals[number - 1].strip())] += 1
                preceding = "\n".join(originals[max(0, number - 8) : number - 1])
                if "F1-PUBLIC-ONLY" not in preceding:
                    findings.append(
                        Finding(relative, number, "literal SecpContext lacks F1-PUBLIC-ONLY marker")
                    )

    findings.extend(
        _exact_allowlist_findings("F1 literal public-only context", literal_actual, literal_expected)
    )
    return CheckResult("F1 secp contexts use syntactically bound fresh entropy", tuple(findings))


def validate(root: pathlib.Path) -> tuple[CheckResult, ...]:
    """Run all ten absorbed/hardened layer guards."""

    root = root.resolve()
    try:
        sources = load_rust_sources(root)
        source_error = None
    except ValueError as error:
        sources = ()
        source_error = str(error)
    results = list(
        check_source_policies(root, _sources=sources, _source_error=source_error)
    )
    results.extend(
        (
            check_f2_feature_boundaries(root),
            check_f5_c1a_boundary(
                root, _sources=sources, _source_error=source_error
            ),
            check_f5_evidence_boundary(root),
            check_f5_signet_static(root),
            check_evidence_only_isolation(root),
            check_store_custody_traits_stay_out_of_the_laboratory(
                root, _sources=sources, _source_error=source_error
            ),
            check_store_never_extracts_adaptor_secret(root),
            check_f1_secp_contexts(root),
        )
    )
    return tuple(results)


def _print_results(results: Sequence[CheckResult]) -> int:
    failures = 0
    for result in results:
        print(f"== {result.name} ==")
        if result.passed:
            suffix = f" ({result.note})" if result.note else ""
            print(f"PASS{suffix}")
        else:
            failures += len(result.findings)
            for finding in result.findings:
                location = finding.path if finding.line == 0 else f"{finding.path}:{finding.line}"
                print(f"FAIL {location}: {finding.message}", file=sys.stderr)
    if failures:
        print(f"LAYER_GUARDS = FAIL ({failures} violation(s))", file=sys.stderr)
        return 1
    print("LAYER_GUARDS = PASS")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    parser.add_argument("--print-layer-packages", action="store_true")
    parser.add_argument("--print-node-members", action="store_true")
    args = parser.parse_args(argv)
    if args.print_layer_packages and args.print_node_members:
        parser.error("package and node listings are mutually exclusive")
    if args.print_layer_packages or args.print_node_members:
        try:
            values = (
                layer_package_names(args.root.resolve())
                if args.print_layer_packages
                else node_member_paths(args.root.resolve())
            )
            print("\n".join(values))
        except ValueError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1
        return 0
    return _print_results(validate(args.root))


if __name__ == "__main__":
    raise SystemExit(main())
