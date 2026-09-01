#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

EXPECTED_COMMIT = "0e17c7f7cd8f0657af176c8852aa4c9949586051"
HERE = Path(__file__).resolve().parents[1]
SOURCE = HERE / "external-gpl/dom-xmr-sidecar"


def fail(message: str) -> None:
    raise SystemExit(message)


def insert_member(cargo: Path, member: str) -> None:
    text = cargo.read_text()
    if f'"{member}"' in text:
        return
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip().startswith("members = [")), None)
    if start is None:
        fail("Eigenwallet workspace members array not found")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip() == "]"), None)
    if end is None:
        fail("Eigenwallet workspace members array is not closed")
    lines.insert(end, f'  "{member}",')
    cargo.write_text("\n".join(lines) + "\n")


def verify_commit(root: Path) -> None:
    if not (root / ".git").exists():
        return
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail("could not resolve Eigenwallet HEAD")
    actual = result.stdout.strip()
    if actual != EXPECTED_COMMIT and os.environ.get("DOM_XMR_ALLOW_SOURCE_DRIFT") != "1":
        fail(
            f"Eigenwallet source drift: expected {EXPECTED_COMMIT}, got {actual}; "
            "set DOM_XMR_ALLOW_SOURCE_DRIFT=1 only after review"
        )


def main() -> None:
    if len(sys.argv) != 2:
        fail(f"usage: {sys.argv[0]} /path/to/eigenwallet-core")
    root = Path(sys.argv[1]).resolve()
    cargo = root / "Cargo.toml"
    if not cargo.is_file() or not (root / "monero-wallet-ng").is_dir():
        fail("target is not an Eigenwallet core checkout")
    verify_commit(root)
    destination = root / "dom-xmr-sidecar"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(SOURCE, destination)
    insert_member(cargo, "dom-xmr-sidecar")
    print(f"installed sidecar at {destination}")
    print("run once without --locked to add the local package, then rerun with --locked")


if __name__ == "__main__":
    main()
