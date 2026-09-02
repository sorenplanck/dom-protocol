#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

closure="reports/WALLET_FINDINGS_CLOSURE.json"
python3 - "$closure" <<'PY'
import json
import os
import pathlib
import re
import subprocess
import sys

required = {
    "C1", "C2", "C3", "C4", "C5",
    "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8",
    "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9",
}
allowed = {"FIXED_TESTED", "CLOSED_NON_REPRODUCIBLE_WITH_PROOF"}
path = pathlib.Path(sys.argv[1])
entries = json.loads(path.read_text(encoding="utf-8"))
ids = [entry.get("id") for entry in entries]
if len(entries) != 22 or set(ids) != required or len(ids) != len(set(ids)):
    raise SystemExit(f"closure ID set mismatch: {ids}")
for entry in entries:
    if entry.get("status") not in allowed:
        raise SystemExit(f"invalid status for {entry.get('id')}: {entry.get('status')}")
    for field in ("root_cause", "production_files", "tests", "verification_commands"):
        if not entry.get(field):
            raise SystemExit(f"missing {field} for {entry.get('id')}")
    for production_file in entry["production_files"]:
        if not pathlib.Path(production_file).is_file():
            raise SystemExit(f"missing production file for {entry['id']}: {production_file}")
    for test_name in entry["tests"]:
        declarations = []
        for root, directories, names in os.walk("."):
            directories[:] = [
                name for name in directories
                if name not in {"target", "node_modules", "dist", ".git"}
            ]
            for name in names:
                if pathlib.Path(name).suffix not in {".rs", ".mjs", ".js"}:
                    continue
                candidate = pathlib.Path(root, name)
                try:
                    source = candidate.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                rust_declared = candidate.suffix == ".rs" and re.search(
                    rf"\bfn\s+{re.escape(test_name)}\s*\(", source
                )
                js_declared = candidate.suffix in {".js", ".mjs"} and re.search(
                    rf"\btest\s*\(\s*['\"]{re.escape(test_name)}['\"]", source
                )
                if rust_declared or js_declared:
                    declarations.append(str(candidate))
        if len(declarations) != 1:
            raise SystemExit(
                f"named test must have exactly one declaration for {entry['id']}: "
                f"{test_name} -> {declarations}"
            )

markdown = pathlib.Path("reports/WALLET_FINDINGS_CLOSURE.md").read_text(encoding="utf-8")
rows = re.findall(
    r"^\|\s*((?:C[1-5])|(?:A[1-8])|(?:M[1-9]))\s*\|\s*"
    r"(FIXED_TESTED|CLOSED_NON_REPRODUCIBLE_WITH_PROOF)\s*\|",
    markdown,
    re.MULTILINE,
)
if len(rows) != 22 or {finding for finding, _ in rows} != required:
    raise SystemExit(f"closure Markdown ID/status rows are not authoritative: {rows}")
json_status = {entry["id"]: entry["status"] for entry in entries}
if any(json_status[finding] != status for finding, status in rows):
    raise SystemExit("closure Markdown and JSON statuses disagree")

base = "bd85ad0e5b52d10ef5c0fb700932231034bc9987"
source_suffixes = {".rs", ".js", ".mjs"}

def declared_tests(source):
    rust = re.findall(
        r"(?s)#\s*\[\s*test\s*\](?:\s*#\s*\[[^\]]+\])*\s*"
        r"(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*\(",
        source,
    )
    javascript = re.findall(r"\btest\s*\(\s*['\"]([^'\"]+)['\"]", source)
    return set(rust + javascript)

def ignored_tests(source):
    ignored = set()
    for match in re.finditer(r"#\s*\[\s*ignore(?:\s*=\s*\"[^\"]*\")?\s*\]", source):
        following = source[match.end():match.end() + 400]
        function = re.search(r"\bfn\s+([A-Za-z0-9_]+)\s*\(", following)
        if function:
            ignored.add(function.group(1))
    return ignored

baseline_paths = subprocess.check_output(
    ["git", "ls-tree", "-r", "--name-only", base], text=True
).splitlines()
baseline_tests = set()
baseline_ignored = set()
for candidate in baseline_paths:
    if pathlib.Path(candidate).suffix not in source_suffixes:
        continue
    try:
        source = subprocess.check_output(
            ["git", "show", f"{base}:{candidate}"], text=True
        )
    except subprocess.CalledProcessError:
        continue
    baseline_tests.update((candidate, name) for name in declared_tests(source))
    baseline_ignored.update((candidate, name) for name in ignored_tests(source))

current_tests = set()
current_ignored = set()
for root, directories, names in os.walk("."):
    directories[:] = [
        name for name in directories
        if name not in {"target", "node_modules", "dist", ".git"}
    ]
    for name in names:
        candidate = pathlib.Path(root, name)
        if candidate.suffix not in source_suffixes:
            continue
        source = candidate.read_text(encoding="utf-8", errors="ignore")
        relative = str(candidate).removeprefix("./")
        current_tests.update((relative, test) for test in declared_tests(source))
        current_ignored.update((relative, test) for test in ignored_tests(source))

removed_tests = sorted(baseline_tests - current_tests)
if removed_tests:
    raise SystemExit(f"pre-campaign tests were deleted or renamed: {removed_tests}")
if current_ignored != baseline_ignored:
    raise SystemExit(
        "ignored-test inventory changed from campaign base: "
        f"before={sorted(baseline_ignored)} after={sorted(current_ignored)}"
    )
print("closure JSON: exact 22-ID set, statuses, files, and named tests validated")
print(
    f"test inventory: {len(baseline_tests)} baseline tests retained; "
    f"ignored inventory unchanged at {len(current_ignored)}"
)
PY

if [[ "${WALLET_VALIDATE_ONLY:-0}" == "1" ]]; then
  exit 0
fi

# One all-target filtered invocation executes every named Rust closure
# regression. The live ignored C1 gate remains explicit below, using the same
# workspace target set so Cargo can reuse the existing artifacts.
cargo test --locked --workspace --all-targets regression_ -- --include-ignored

cargo test --locked --workspace --all-targets \
  live_mainnet_genesis_wallet_syncs_at_zero_without_mining -- --ignored

cargo test --locked --workspace --all-targets

cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo build --locked --workspace --release

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "missing required gate: install with 'cargo install cargo-audit --locked'" >&2
  exit 1
fi
if ! command -v cargo-deny >/dev/null 2>&1; then
  echo "missing required gate: install with 'cargo install cargo-deny --locked'" >&2
  exit 1
fi
if ! cargo audit; then
  echo "cargo audit could not refresh its read-only advisory cache; retrying against the installed cache without fetching" >&2
  cargo audit --no-fetch
fi
cargo deny check bans licenses sources
if ! cargo deny check advisories; then
  echo "cargo deny could not lock its read-only advisory cache; checking a private writable copy of the installed cache without fetching" >&2
  deny_cache_root="$(mktemp -d /tmp/dom-wallet-cargo-deny.XXXXXX)"
  cargo_cache_root="${CARGO_HOME:-${HOME}/.cargo}"
  mkdir -p "$deny_cache_root/advisory-dbs"
  cp -a "$cargo_cache_root"/advisory-dbs/advisory-db-* \
    "$deny_cache_root/advisory-dbs/"
  ln -s "$cargo_cache_root/registry" "$deny_cache_root/registry"
  ln -s "$cargo_cache_root/git" "$deny_cache_root/git"
  cargo metadata --locked --offline --format-version 1 \
    >"$deny_cache_root/metadata.json"
  CARGO_HOME="$deny_cache_root" cargo deny --offline check --disable-fetch \
    --metadata-path "$deny_cache_root/metadata.json" advisories
fi

# Keep npm installation after the Cargo gates: src-tauri's build script watches
# the frontend tree, so reinstalling dependencies earlier would invalidate the
# already-verified Rust artifacts and force an unrelated relink.
(
  cd frontend
  npm_ci_log="$(mktemp)"
  trap 'rm -f "$npm_ci_log"' EXIT
  if npm ci 2>&1 | tee "$npm_ci_log"; then
    :
  else
    npm_ci_rc="${PIPESTATUS[0]}"
    if [[ "$npm_ci_rc" -ne 1 ]] \
      || ! grep -Fq "Error: spawnSync $PWD/node_modules/esbuild/bin/esbuild EPERM" "$npm_ci_log" \
      || ! grep -Fq "status: 0" "$npm_ci_log"; then
      exit "$npm_ci_rc"
    fi
    echo "plain npm ci was denied by the execution sandbox; retrying the same lockfile from the offline cache without lifecycle scripts" >&2
    npm ci --ignore-scripts --offline
  fi
  rm -f "$npm_ci_log"
  trap - EXIT
  npm test
  npm run typecheck
  npm run build
)

python3 - <<'PY'
import re
import subprocess

base = "bd85ad0e5b52d10ef5c0fb700932231034bc9987"
before = subprocess.check_output(["git", "show", f"{base}:Cargo.lock"], text=True)
after = open("Cargo.lock", encoding="utf-8").read()
pattern = re.compile(r"source = \"git\+([^\"]+)\"")
before_pins = sorted(pattern.findall(before))
after_pins = sorted(pattern.findall(after))
if before_pins != after_pins:
    raise SystemExit("exact git dependency pins changed from the frozen campaign base")
print("exact git dependency pins unchanged from campaign base")
PY

git diff --check
