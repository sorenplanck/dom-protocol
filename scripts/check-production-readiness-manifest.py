#!/usr/bin/env python3
"""Fail-closed structural gate for the DOM production-readiness register."""

from __future__ import annotations

import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    ROOT
    / "docs/interop/reports/DOM-PRODUCTION-READINESS-MANIFEST-2026-08-27.json"
)
COMMIT = re.compile(r"^[0-9a-f]{40}$")
REQUIREMENT_ID = re.compile(r"^PRD-[0-9]{3}$")
BASELINE_ID = re.compile(r"^BASE-[0-9]{3}$")
AREAS = {
    "route-runtime",
    "daemon",
    "chain-runtime",
    "relay",
    "wallet",
    "contracts",
    "solver",
    "configuration",
    "build-release",
    "platform",
    "network-enablement",
    "testing",
    "operations",
}
PRIORITIES = {"P0", "P1", "P2", "P3"}
STATUSES = {"missing", "partial", "worktree-only", "present", "intentional-exclusion"}
FORBIDDEN_PRODUCT_TARGETS = (
    "crates/f2-harness",
    "crates/f3-harness",
    "crates/f4-harness",
    "crates/f5-e2e",
    "crates/f7-e2e",
)
MANDATORY = {
    "PRD-001",  # route executor
    "PRD-002",  # route store
    "PRD-003",  # daemon
    "PRD-004",  # secret handoff
    "PRD-009",  # relay -> store
    "PRD-011",  # DOM wallet
    "PRD-012",  # EVM wallet
    "PRD-013",  # Bitcoin authority
    "PRD-016",  # contracts in snapshot
    "PRD-017",  # deployments
    "PRD-019",  # live bond
    "PRD-021",  # solver service
    "PRD-022",  # inventory
    "PRD-025",  # registry
    "PRD-026",  # feature closure
    "PRD-031",  # composed system E2E
    "PRD-032",  # fault matrix
    "PRD-035",  # operations alerts
    "PRD-036",  # disaster recovery
}


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def dependency_cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    """Return dependency cycles, with each cycle reported only once."""

    state: dict[str, int] = {}
    stack: list[str] = []
    cycles: list[list[str]] = []

    def visit(node: str) -> None:
        marker = state.get(node, 0)
        if marker == 2:
            return
        if marker == 1:
            start = stack.index(node)
            cycles.append(stack[start:] + [node])
            return
        state[node] = 1
        stack.append(node)
        for dependency in graph.get(node, []):
            if dependency in graph:
                visit(dependency)
        stack.pop()
        state[node] = 2

    for item in graph:
        if state.get(item, 0) == 0:
            visit(item)
    return cycles


def validate(path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read manifest: {exc}"]

    require(payload.get("schema") == "dom.production-readiness.v1", "bad schema", errors)
    audit = payload.get("audit", {})
    require(
        bool(COMMIT.fullmatch(str(audit.get("snapshot_commit", "")))),
        "bad snapshot commit",
        errors,
    )
    require(audit.get("snapshot_verdict") == "no-go-for-real-value", "unsafe verdict", errors)
    require(audit.get("worktree_is_not_snapshot") is True, "snapshot/worktree boundary missing", errors)
    require(audit.get("push_performed") is False, "manifest claims a push was performed", errors)

    baselines = payload.get("baseline", [])
    baseline_ids: set[str] = set()
    require(isinstance(baselines, list) and bool(baselines), "baseline is empty", errors)
    for index, item in enumerate(baselines):
        item_id = str(item.get("id", f"baseline-{index}"))
        require(bool(BASELINE_ID.fullmatch(item_id)), f"{item_id}: bad baseline id", errors)
        require(item_id not in baseline_ids, f"{item_id}: duplicate baseline id", errors)
        baseline_ids.add(item_id)
        require(bool(item.get("capability")), f"{item_id}: missing capability", errors)
        require(bool(item.get("evidence")), f"{item_id}: missing evidence", errors)

    items = payload.get("requirements", [])
    require(isinstance(items, list) and bool(items), "requirement list is empty", errors)
    by_id: dict[str, dict] = {}
    graph: dict[str, list[str]] = {}
    for index, item in enumerate(items):
        item_id = str(item.get("id", f"requirement-{index}"))
        require(bool(REQUIREMENT_ID.fullmatch(item_id)), f"{item_id}: bad requirement id", errors)
        require(item_id not in by_id, f"{item_id}: duplicate id", errors)
        by_id[item_id] = item
        require(item.get("area") in AREAS, f"{item_id}: unknown area", errors)
        require(item.get("priority") in PRIORITIES, f"{item_id}: unknown priority", errors)
        require(item.get("snapshot_status") in STATUSES, f"{item_id}: bad snapshot status", errors)
        require(item.get("worktree_status") in STATUSES, f"{item_id}: bad worktree status", errors)
        require(isinstance(item.get("release_blocker"), bool), f"{item_id}: bad blocker flag", errors)
        require(bool(item.get("gap")), f"{item_id}: missing gap", errors)
        require(bool(item.get("evidence")), f"{item_id}: missing code evidence", errors)
        require(bool(item.get("target")), f"{item_id}: missing target", errors)
        tests = item.get("acceptance_tests")
        require(isinstance(tests, list) and bool(tests), f"{item_id}: missing acceptance tests", errors)
        dependencies = item.get("depends_on")
        require(isinstance(dependencies, list), f"{item_id}: dependencies are not a list", errors)
        graph[item_id] = dependencies if isinstance(dependencies, list) else []

        if item.get("priority") == "P0":
            require(item.get("release_blocker") is True, f"{item_id}: P0 is not a blocker", errors)
            require(len(tests or []) >= 3, f"{item_id}: P0 needs at least three acceptance tests", errors)
        if item.get("release_blocker"):
            require(
                item.get("snapshot_status") not in {"present", "intentional-exclusion"},
                f"{item_id}: blocker is already present or intentionally excluded",
                errors,
            )
        target = str(item.get("target", ""))
        require(
            not any(forbidden in target for forbidden in FORBIDDEN_PRODUCT_TARGETS),
            f"{item_id}: acceptance harness is named as product target",
            errors,
        )
        require(item_id not in graph[item_id], f"{item_id}: self dependency", errors)

    require(MANDATORY <= set(by_id), "mandatory production domains are missing", errors)
    for item_id, dependencies in graph.items():
        for dependency in dependencies:
            require(dependency in by_id, f"{item_id}: unknown dependency {dependency}", errors)
    for cycle in dependency_cycles(graph):
        errors.append(f"dependency cycle: {' -> '.join(cycle)}")

    contract = by_id.get("PRD-016", {})
    require(contract.get("snapshot_status") == "missing", "PRD-016: contracts counted in snapshot", errors)
    require(
        contract.get("worktree_status") == "worktree-only",
        "PRD-016: local contracts are not marked worktree-only",
        errors,
    )

    milestones = payload.get("milestones", [])
    require(isinstance(milestones, list) and bool(milestones), "milestones are empty", errors)
    milestone_ids: set[str] = set()
    covered: set[str] = set()
    for index, milestone in enumerate(milestones):
        milestone_id = str(milestone.get("id", f"milestone-{index}"))
        require(milestone_id not in milestone_ids, f"{milestone_id}: duplicate milestone", errors)
        milestone_ids.add(milestone_id)
        requirement_ids = milestone.get("requirements")
        require(
            isinstance(requirement_ids, list) and bool(requirement_ids),
            f"{milestone_id}: empty requirements",
            errors,
        )
        require(bool(milestone.get("exit")), f"{milestone_id}: missing exit criterion", errors)
        for requirement_id in requirement_ids or []:
            require(
                requirement_id in by_id,
                f"{milestone_id}: unknown requirement {requirement_id}",
                errors,
            )
            require(
                requirement_id not in covered,
                f"{milestone_id}: requirement {requirement_id} is assigned twice",
                errors,
            )
            covered.add(requirement_id)

    blockers = {item_id for item_id, item in by_id.items() if item.get("release_blocker")}
    require(blockers <= covered, "release blockers are missing from milestones", errors)
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
