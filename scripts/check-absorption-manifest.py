#!/usr/bin/env python3
"""Fail-closed structural gate for the code-first absorption decision record."""

from __future__ import annotations

import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    ROOT
    / "docs/interop/reports/DOM-CODE-FIRST-ABSORPTION-MANIFEST-2026-08-27.json"
)
SHA256_HEX = re.compile(r"^[0-9a-f]{40}$")
SOURCES = {"cipher", "kaystra", "kael", "keystone"}
DECISIONS = {"adopt", "adapt", "quarantine", "reject"}
PRIORITIES = {"P0", "P1", "P2", "P3", "research"}
RESTRICTED = {"cipher", "kaystra", "keystone"}


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def validate(path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read manifest: {exc}"]

    require(payload.get("schema") == "dom.absorption-plan.v1", "bad schema", errors)
    dom = payload.get("dom", {})
    require(bool(SHA256_HEX.fullmatch(str(dom.get("commit", "")))), "bad DOM commit", errors)

    source_records = payload.get("sources", {})
    require(set(source_records) == SOURCES, "source set is incomplete or unexpected", errors)
    for name, record in source_records.items():
        require(
            bool(SHA256_HEX.fullmatch(str(record.get("commit", "")))),
            f"{name}: bad commit",
            errors,
        )
        require(bool(record.get("license_policy")), f"{name}: missing license policy", errors)

    seen: set[str] = set()
    items = payload.get("decisions", [])
    require(isinstance(items, list) and bool(items), "decision list is empty", errors)
    for index, item in enumerate(items):
        prefix = str(item.get("id", f"item-{index}"))
        require(prefix not in seen, f"{prefix}: duplicate id", errors)
        seen.add(prefix)
        source = item.get("source")
        decision = item.get("decision")
        priority = item.get("priority")
        require(source in SOURCES, f"{prefix}: unknown source", errors)
        require(decision in DECISIONS, f"{prefix}: unknown decision", errors)
        require(priority in PRIORITIES, f"{prefix}: unknown priority", errors)
        require(bool(item.get("mechanism")), f"{prefix}: missing mechanism", errors)
        require(bool(item.get("rationale")), f"{prefix}: missing rationale", errors)
        require(bool(item.get("production_copy_policy")), f"{prefix}: missing copy policy", errors)
        require(bool(item.get("source_evidence")), f"{prefix}: missing code evidence", errors)

        if decision in {"adopt", "adapt"} and priority in {"P0", "P1"}:
            require(item.get("target") not in {None, "", "none"}, f"{prefix}: missing target", errors)
            require(bool(item.get("acceptance_tests")), f"{prefix}: missing acceptance tests", errors)
        if decision in {"quarantine", "reject"}:
            require(priority in {"P3", "research"}, f"{prefix}: rejected item is release-prioritized", errors)
        if source in RESTRICTED:
            policy = str(item.get("production_copy_policy", ""))
            require("direct-copy" not in policy, f"{prefix}: restricted source allows direct copy", errors)

    required_p0 = {"CIP-01", "KAY-01", "KAY-05", "KAE-01", "KEY-01", "KEY-07"}
    require(required_p0 <= seen, "mandatory P0 controls are missing", errors)
    return errors


def main() -> int:
    path = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_MANIFEST
    errors = validate(path)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"PASS: validated {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
