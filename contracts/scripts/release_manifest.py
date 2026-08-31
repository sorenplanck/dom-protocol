#!/usr/bin/env python3
"""Build and verify a fail-closed DOM EVM deployment release record.

The record is public metadata. It intentionally contains no RPC endpoint,
signing key, credential, transaction replacement policy or registry signing
material. The deployment registry authorities sign a separate canonical
registry manifest after reviewing this record.
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Protocol, Sequence


SCHEMA = "dom.evm-contract-release.v1"
DEPENDENCY_SCHEMA = "dom.evm-contract-dependencies.v1"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_FILES = 256
MAX_RUNTIME_BYTES = 24_576
ZERO32 = "0x" + "00" * 32
HEX_RE = re.compile(r"^0x[0-9a-fA-F]*$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
DIGEST_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")

CONTRACTS = (
    ("native", "ConditionLockV2", "src/ConditionLockV2.sol"),
    ("erc20", "ConditionLockERC20V2", "src/ConditionLockERC20V2.sol"),
)
DEPLOY_ARTIFACT = ("DeployScript", "script/Deploy.s.sol")

EXPECTED_SOLC = "0.8.24+commit.e11b9ed9"
EXPECTED_SETTINGS = {
    "evmVersion": "shanghai",
    "libraries": {},
    "metadata": {"bytecodeHash": "none"},
    "optimizer": {"enabled": True, "runs": 20_000},
    "viaIR": False,
}

REQUIRED_METHOD_IDENTIFIERS = {
    "addressOfScalarTimesG(uint256)",
    "claim(bytes32,uint256)",
    "deriveBinding((bytes32,uint8,bytes32,bytes32,bytes32,address,uint256,address,address,uint64))",
    "deriveLockId((bytes32,uint8,bytes32,bytes32,bytes32,address,uint256,address,address,uint64),address)",
    "lockOf(bytes32)",
    "open((bytes32,uint8,bytes32,bytes32,bytes32,address,uint256,address,address,uint64))",
    "pendingWithdrawals(address,address)",
    "refund(bytes32)",
    "withdraw(address)",
    "withdrawAmount(address,address,uint256)",
    "withdrawTo(address,address)",
}
REQUIRED_EVENTS = {
    "Claimed(bytes32,bytes32,address,uint256)",
    "LockOpened(bytes32,bytes32,address,address,address,uint256,address,uint64)",
    "PayoutDeferred(address,address,uint256)",
    "Refunded(bytes32,bytes32,address,uint256)",
    "Withdrawal(address,address,address,uint256)",
}


class ReleaseError(RuntimeError):
    """A release fact is absent, contradictory, oversized or noncanonical."""


class RpcPort(Protocol):
    def call(self, method: str, params: Sequence[Any]) -> Any: ...


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ReleaseError("value cannot be represented as canonical JSON") from exc


def display_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ReleaseError("value cannot be represented as display JSON") from exc


def strict_json_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> None:
    raise ReleaseError(f"JSON contains non-finite number: {value}")


def decode_json(raw: bytes) -> Any:
    return json.loads(
        raw,
        object_pairs_hook=strict_json_object,
        parse_constant=reject_json_constant,
    )


def blake2b256(domain: bytes, payload: bytes) -> str:
    h = hashlib.blake2b(digest_size=32)
    h.update(domain)
    h.update(b"\x00")
    h.update(payload)
    return "0x" + h.hexdigest()


def digest_files(domain: bytes, files: Iterable[tuple[str, bytes]]) -> str:
    h = hashlib.blake2b(digest_size=32)
    h.update(domain)
    h.update(b"\x00")
    previous: str | None = None
    for path, content in sorted(files, key=lambda item: item[0]):
        if previous == path:
            raise ReleaseError(f"duplicate source path: {path}")
        previous = path
        path_bytes = path.encode("utf-8")
        h.update(len(path_bytes).to_bytes(4, "big"))
        h.update(path_bytes)
        h.update(len(content).to_bytes(8, "big"))
        h.update(content)
    return "0x" + h.hexdigest()


def parse_hex(value: Any, *, name: str, size: int | None = None) -> bytes:
    if not isinstance(value, str) or not HEX_RE.fullmatch(value) or len(value) % 2 != 0:
        raise ReleaseError(f"{name} is not canonical 0x-prefixed hex")
    try:
        decoded = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise ReleaseError(f"{name} is not hex") from exc
    if size is not None and len(decoded) != size:
        raise ReleaseError(f"{name} must be {size} bytes")
    return decoded


def canonical_hex(value: Any, *, name: str, size: int | None = None) -> str:
    return "0x" + parse_hex(value, name=name, size=size).hex()


def canonical_nonzero_hex(value: Any, *, name: str, size: int) -> str:
    decoded = parse_hex(value, name=name, size=size)
    if decoded == bytes(size):
        raise ReleaseError(f"{name} must not be zero")
    return "0x" + decoded.hex()


def parse_quantity(value: Any, *, name: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value):
        raise ReleaseError(f"{name} is not a canonical JSON-RPC quantity")
    return int(value, 16)


def require_mapping(value: Any, *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseError(f"{name} must be an object")
    return value


def require_list(value: Any, *, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReleaseError(f"{name} must be an array")
    return value


def read_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ReleaseError(f"cannot stat {path}") from exc
    if size <= 0 or size > max_bytes:
        raise ReleaseError(f"JSON file has invalid size: {path}")
    try:
        raw = path.read_bytes()
        return decode_json(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"invalid JSON: {path}") from exc


def safe_project_file(project_root: Path, relative: str) -> tuple[str, bytes]:
    if not relative or "\\" in relative:
        raise ReleaseError(f"noncanonical source path: {relative!r}")
    relative_path = Path(relative)
    if relative_path.is_absolute() or any(part in ("", ".", "..") for part in relative_path.parts):
        raise ReleaseError(f"unsafe source path: {relative!r}")
    root = project_root.resolve()
    resolved = (root / relative_path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ReleaseError(f"source escapes project root: {relative!r}") from exc
    try:
        if not resolved.is_file() or resolved.stat().st_size > MAX_SOURCE_BYTES:
            raise ReleaseError(f"source missing or oversized: {relative}")
        content = resolved.read_bytes()
    except OSError as exc:
        raise ReleaseError(f"cannot read source: {relative}") from exc
    return relative_path.as_posix(), content


def artifact_path(artifacts_dir: Path, source: str, contract_name: str) -> Path:
    return artifacts_dir / f"{Path(source).name}/{contract_name}.json"


@dataclass(frozen=True)
class Artifact:
    name: str
    source: str
    abi: list[Any]
    method_identifiers: Mapping[str, Any]
    creation_code: bytes
    runtime_code: bytes
    metadata: Mapping[str, Any]


def load_artifact(artifacts_dir: Path, contract_name: str, source: str) -> Artifact:
    path = artifact_path(artifacts_dir, source, contract_name)
    raw = require_mapping(read_json(path), name=str(path))
    abi = require_list(raw.get("abi"), name=f"{contract_name}.abi")
    method_identifiers = require_mapping(
        raw.get("methodIdentifiers"), name=f"{contract_name}.methodIdentifiers"
    )
    bytecode = require_mapping(raw.get("bytecode"), name=f"{contract_name}.bytecode")
    deployed = require_mapping(raw.get("deployedBytecode"), name=f"{contract_name}.deployedBytecode")
    if bytecode.get("linkReferences") not in ({}, None) or deployed.get("linkReferences") not in ({}, None):
        raise ReleaseError(f"{contract_name} unexpectedly requires linked libraries")
    if deployed.get("immutableReferences") not in ({}, None):
        raise ReleaseError(f"{contract_name} unexpectedly contains immutables")
    creation = parse_hex(bytecode.get("object"), name=f"{contract_name}.creationCode")
    runtime = parse_hex(deployed.get("object"), name=f"{contract_name}.runtimeCode")
    if not creation or not runtime or len(runtime) > MAX_RUNTIME_BYTES:
        raise ReleaseError(f"{contract_name} bytecode is empty or exceeds EIP-170")
    metadata = require_mapping(raw.get("metadata"), name=f"{contract_name}.metadata")
    return Artifact(
        name=contract_name,
        source=source,
        abi=abi,
        method_identifiers=method_identifiers,
        creation_code=creation,
        runtime_code=runtime,
        metadata=metadata,
    )


def abi_type(parameter: Mapping[str, Any]) -> str:
    kind = parameter.get("type")
    if not isinstance(kind, str):
        raise ReleaseError("ABI parameter lacks type")
    if not kind.startswith("tuple"):
        return kind
    components = require_list(parameter.get("components"), name="ABI tuple components")
    inner = ",".join(abi_type(require_mapping(item, name="ABI tuple component")) for item in components)
    return f"({inner}){kind[5:]}"


def event_signatures(abi: Sequence[Any]) -> set[str]:
    signatures: set[str] = set()
    for item in abi:
        entry = require_mapping(item, name="ABI entry")
        if entry.get("type") != "event":
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            raise ReleaseError("ABI event lacks name")
        inputs = require_list(entry.get("inputs"), name=f"event {name} inputs")
        args = ",".join(abi_type(require_mapping(value, name=f"event {name} input")) for value in inputs)
        signatures.add(f"{name}({args})")
    return signatures


def validate_runtime_interface(artifact: Artifact) -> None:
    methods = set(artifact.method_identifiers)
    missing_methods = sorted(REQUIRED_METHOD_IDENTIFIERS - methods)
    missing_events = sorted(REQUIRED_EVENTS - event_signatures(artifact.abi))
    if missing_methods or missing_events:
        raise ReleaseError(
            f"{artifact.name} is incompatible with adapter-evm; "
            f"missing methods={missing_methods}, events={missing_events}"
        )


def normalized_compiler(artifact: Artifact) -> tuple[dict[str, Any], dict[str, str]]:
    compiler = require_mapping(artifact.metadata.get("compiler"), name=f"{artifact.name}.compiler")
    version = compiler.get("version")
    if version != EXPECTED_SOLC:
        raise ReleaseError(f"{artifact.name} compiler is {version!r}, expected {EXPECTED_SOLC}")
    settings_raw = require_mapping(artifact.metadata.get("settings"), name=f"{artifact.name}.settings")
    settings = dict(settings_raw)
    target = require_mapping(settings.pop("compilationTarget", None), name="compilationTarget")
    if target != {artifact.source: artifact.name}:
        raise ReleaseError(f"{artifact.name} compilation target is contradictory")
    remappings_raw = require_list(settings.pop("remappings", []), name="compiler remappings")
    if any(not isinstance(value, str) for value in remappings_raw):
        raise ReleaseError("compiler remapping is not text")
    remappings = set(remappings_raw)
    settings.setdefault("viaIR", False)
    if settings != EXPECTED_SETTINGS:
        raise ReleaseError(f"{artifact.name} compiler settings drifted: {settings!r}")
    sources = require_mapping(artifact.metadata.get("sources"), name=f"{artifact.name}.sources")
    if not sources or len(sources) > MAX_SOURCE_FILES:
        raise ReleaseError(f"{artifact.name} metadata has no source list")
    source_hashes: dict[str, str] = {}
    for path, raw_source in sources.items():
        if not isinstance(path, str):
            raise ReleaseError(f"{artifact.name} metadata contains a non-text source path")
        source = require_mapping(raw_source, name=f"{artifact.name} source metadata")
        source_hashes[path] = canonical_hex(
            source.get("keccak256"), name=f"{artifact.name} source hash", size=32
        )
    return {"solc": version, "settings": settings}, source_hashes


def merge_source_hashes(target: dict[str, str], incoming: Mapping[str, str]) -> None:
    for path, expected in incoming.items():
        previous = target.get(path)
        if previous is not None and previous != expected:
            raise ReleaseError(f"compiler metadata disagrees about source {path}")
        target[path] = expected


def load_dependency_lock(project_root: Path) -> list[dict[str, str]]:
    path = project_root / "dependencies.lock.json"
    lock = require_mapping(read_json(path), name="dependency lock")
    if lock.get("schema") != DEPENDENCY_SCHEMA:
        raise ReleaseError("unsupported dependency lock schema")
    dependencies = require_list(lock.get("dependencies"), name="dependencies")
    normalized: list[dict[str, str]] = []
    previous: str | None = None
    seen_paths: set[str] = set()
    for raw in dependencies:
        item = require_mapping(raw, name="dependency")
        required = {
            "name",
            "install_path",
            "repository",
            "revision",
            "version",
            "release_source_digest",
        }
        if set(item) != required:
            raise ReleaseError("dependency lock entry has unknown or missing fields")
        if any(not isinstance(item[key], str) or not item[key] for key in required):
            raise ReleaseError("dependency lock entry has an invalid string")
        name = item["name"]
        install_path = Path(item["install_path"]).as_posix()
        if previous is not None and previous >= name:
            raise ReleaseError("dependency lock entries are not strictly sorted")
        previous = name
        if install_path in seen_paths or install_path.startswith("/") or ".." in Path(install_path).parts:
            raise ReleaseError("dependency install path is duplicate or unsafe")
        seen_paths.add(install_path)
        if not REVISION_RE.fullmatch(item["revision"]):
            raise ReleaseError(f"dependency {name} revision is not an exact Git object")
        if not DIGEST_RE.fullmatch(item["release_source_digest"]):
            raise ReleaseError(f"dependency {name} source digest is invalid")
        repository = urllib.parse.urlparse(item["repository"])
        if repository.scheme != "https" or not repository.netloc:
            raise ReleaseError(f"dependency {name} repository must be HTTPS")
        package = require_mapping(
            read_json(project_root / install_path / "package.json"), name=f"{name} package.json"
        )
        if package.get("version") != item["version"]:
            raise ReleaseError(f"dependency {name} version does not match its lock")
        normalized.append({key: item[key] for key in sorted(required)})
    if not normalized:
        raise ReleaseError("dependency lock is empty")
    return normalized


def source_bundle(
    project_root: Path,
    compiled_source_hashes: Mapping[str, str],
    dependencies: Sequence[Mapping[str, str]],
    *,
    cast_binary: str,
    enforce_dependency_digests: bool,
) -> tuple[list[dict[str, Any]], str, dict[str, str]]:
    if not compiled_source_hashes or len(compiled_source_hashes) > MAX_SOURCE_FILES:
        raise ReleaseError("compiled source set is empty or oversized")
    source_paths = set(compiled_source_hashes)
    source_paths.update(("foundry.toml", "remappings.txt", "script/Deploy.s.sol"))
    files = [safe_project_file(project_root, path) for path in source_paths]
    by_path = dict(files)
    for path, expected in compiled_source_hashes.items():
        if keccak256(by_path[path], cast_binary) != expected:
            raise ReleaseError(f"compiled artifact metadata does not match source {path}")
    source_records = [
        {
            "blake2b256": blake2b256(b"DOM:EVM-release-source-file:v1", content),
            "bytes": len(content),
            "path": path,
        }
        for path, content in sorted(files)
    ]
    dependency_digests: dict[str, str] = {}
    for dependency in dependencies:
        prefix = dependency["install_path"] + "/"
        selected = [(path, content) for path, content in files if path.startswith(prefix)]
        if not selected:
            raise ReleaseError(f"dependency {dependency['name']} contributed no compiled source")
        actual = digest_files(b"DOM:EVM-release-dependency-sources:v1", selected)
        dependency_digests[dependency["name"]] = actual
        if enforce_dependency_digests and actual != dependency["release_source_digest"].lower():
            raise ReleaseError(
                f"dependency {dependency['name']} source digest mismatch: "
                f"locked {dependency['release_source_digest']}, actual {actual}"
            )
    return (
        source_records,
        digest_files(b"DOM:EVM-release-source-bundle:v1", files),
        dependency_digests,
    )


@functools.lru_cache(maxsize=512)
def keccak256(data: bytes, cast_binary: str) -> str:
    try:
        completed = subprocess.run(
            [cast_binary, "keccak"],
            check=False,
            capture_output=True,
            input=data,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseError("cannot execute cast keccak") from exc
    try:
        output = completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ReleaseError("cast keccak returned non-text output") from exc
    if completed.returncode != 0 or not DIGEST_RE.fullmatch(output):
        raise ReleaseError("cast keccak failed")
    return output.lower()


@contextlib.contextmanager
def verified_release_artifacts(
    project_root: Path,
    reviewed_artifacts_dir: Path,
    forge_binary: str,
) -> Iterator[Path]:
    """Compile from source and require the reviewed artifacts to be identical."""

    with tempfile.TemporaryDirectory(prefix="dom-evm-release-compile-") as directory:
        temporary = Path(directory)
        out = temporary / "out"
        command = [
            forge_binary,
            "build",
            "src/ConditionLockV2.sol",
            "src/ConditionLockERC20V2.sol",
            "script/Deploy.s.sol",
            "--offline",
            "--no-cache",
            "--out",
            str(out),
            "--cache-path",
            str(temporary / "cache"),
            "--build-info",
            "--build-info-path",
            str(temporary / "build-info"),
            "-D",
            "warnings",
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=project_root,
                check=False,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReleaseError("clean release compilation could not run") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout)[-2_000:].strip()
            raise ReleaseError(f"clean release compilation failed: {detail}")
        for contract_name, source in (
            *((name, source) for _, name, source in CONTRACTS),
            DEPLOY_ARTIFACT,
        ):
            fresh = artifact_path(out, source, contract_name)
            reviewed = artifact_path(reviewed_artifacts_dir, source, contract_name)
            try:
                fresh_json = require_mapping(read_json(fresh), name=f"fresh {contract_name} artifact")
                reviewed_json = require_mapping(
                    read_json(reviewed), name=f"reviewed {contract_name} artifact"
                )
            except OSError as exc:
                raise ReleaseError(f"release artifact missing for {contract_name}") from exc

            def release_view(raw: Mapping[str, Any]) -> dict[str, Any]:
                bytecode = require_mapping(raw.get("bytecode"), name="release bytecode")
                deployed = require_mapping(raw.get("deployedBytecode"), name="release deployed bytecode")
                return {
                    "abi": raw.get("abi"),
                    "bytecode": {
                        "linkReferences": bytecode.get("linkReferences"),
                        "object": bytecode.get("object"),
                    },
                    "deployedBytecode": {
                        "immutableReferences": deployed.get("immutableReferences"),
                        "linkReferences": deployed.get("linkReferences"),
                        "object": deployed.get("object"),
                    },
                    "metadata": raw.get("metadata"),
                    "methodIdentifiers": raw.get("methodIdentifiers"),
                    "rawMetadata": raw.get("rawMetadata"),
                }

            if canonical_json_bytes(release_view(fresh_json)) != canonical_json_bytes(
                release_view(reviewed_json)
            ):
                raise ReleaseError(
                    f"reviewed {contract_name} artifact differs from a clean source compilation"
                )
        yield out


def rlp_bytes(value: bytes) -> bytes:
    if len(value) == 1 and value[0] < 0x80:
        return value
    if len(value) <= 55:
        return bytes([0x80 + len(value)]) + value
    length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([0xB7 + len(length)]) + length + value


def rlp_list(values: Sequence[bytes]) -> bytes:
    payload = b"".join(rlp_bytes(value) for value in values)
    if len(payload) <= 55:
        return bytes([0xC0 + len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(length)]) + length + payload


def create_address(sender: str, nonce: int, cast_binary: str) -> str:
    sender_bytes = parse_hex(sender, name="deployer", size=20)
    nonce_bytes = b"" if nonce == 0 else nonce.to_bytes((nonce.bit_length() + 7) // 8, "big")
    digest = parse_hex(keccak256(rlp_list((sender_bytes, nonce_bytes)), cast_binary), name="CREATE digest", size=32)
    return "0x" + digest[-20:].hex()


class HttpJsonRpc:
    def __init__(self, url: str, *, timeout_seconds: float = 20.0) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password:
            raise ReleaseError("RPC URL must be credential-free HTTP(S)")
        self._url = url
        self._timeout = timeout_seconds
        self._request_id = 0

    def call(self, method: str, params: Sequence[Any]) -> Any:
        self._request_id += 1
        payload = canonical_json_bytes(
            {"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": list(params)}
        )
        request = urllib.request.Request(
            self._url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                length = response.headers.get("Content-Length")
                if length is not None and int(length) > MAX_JSON_BYTES:
                    raise ReleaseError("RPC response exceeds limit")
                raw = response.read(MAX_JSON_BYTES + 1)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise ReleaseError(f"RPC unavailable while calling {method}") from exc
        if len(raw) > MAX_JSON_BYTES:
            raise ReleaseError("RPC response exceeds limit")
        try:
            decoded = require_mapping(decode_json(raw), name="RPC response")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReleaseError("RPC returned invalid JSON") from exc
        if decoded.get("id") != self._request_id or decoded.get("jsonrpc") != "2.0":
            raise ReleaseError("RPC response id/version mismatch")
        if "error" in decoded:
            raise ReleaseError(f"RPC refused {method}")
        if "result" not in decoded:
            raise ReleaseError("RPC response lacks result")
        return decoded["result"]


def find_broadcast_contract(
    broadcast: Mapping[str, Any], contract_name: str
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    transactions = require_list(broadcast.get("transactions"), name="broadcast transactions")
    matches = [
        require_mapping(tx, name="broadcast transaction")
        for tx in transactions
        if isinstance(tx, dict) and tx.get("contractName") == contract_name
    ]
    if len(matches) != 1:
        raise ReleaseError(f"broadcast must contain exactly one {contract_name} transaction")
    entry = matches[0]
    if entry.get("transactionType") != "CREATE" or entry.get("arguments") is not None:
        raise ReleaseError(f"{contract_name} must be a constructor-argument-free CREATE deployment")
    if entry.get("additionalContracts") not in ([], None):
        raise ReleaseError(f"{contract_name} broadcast has unexpected additional contracts")
    transaction = require_mapping(entry.get("transaction"), name=f"{contract_name} broadcast transaction")
    tx_hash = canonical_nonzero_hex(
        entry.get("hash"), name=f"{contract_name} tx hash", size=32
    )
    receipts = require_list(broadcast.get("receipts"), name="broadcast receipts")
    receipt_matches = [
        require_mapping(value, name="broadcast receipt")
        for value in receipts
        if isinstance(value, dict)
        and isinstance(value.get("transactionHash"), str)
        and value["transactionHash"].lower() == tx_hash
    ]
    if len(receipt_matches) != 1:
        raise ReleaseError(f"broadcast must contain exactly one receipt for {contract_name}")
    return entry, receipt_matches[0]


def block_record(rpc: RpcPort, block_number: int, expected_hash: str | None = None) -> dict[str, Any]:
    block = require_mapping(
        rpc.call("eth_getBlockByNumber", [hex(block_number), False]), name=f"block {block_number}"
    )
    number = parse_quantity(block.get("number"), name=f"block {block_number} number")
    if number != block_number:
        raise ReleaseError("RPC returned the wrong block")
    block_hash = canonical_nonzero_hex(
        block.get("hash"), name=f"block {block_number} hash", size=32
    )
    if expected_hash is not None and block_hash != expected_hash:
        raise ReleaseError(f"block {block_number} is no longer canonical")
    return {
        "hash": block_hash,
        "number": number,
        "timestamp": parse_quantity(block.get("timestamp"), name=f"block {block_number} timestamp"),
    }


def deployment_contract_record(
    *,
    rpc: RpcPort,
    broadcast: Mapping[str, Any],
    artifact: Artifact,
    role: str,
    chain_id: int,
    finalized_number: int,
    cast_binary: str,
) -> dict[str, Any]:
    entry, broadcast_receipt = find_broadcast_contract(broadcast, artifact.name)
    transaction = require_mapping(entry.get("transaction"), name=f"{artifact.name} transaction")
    tx_chain_id = parse_quantity(transaction.get("chainId"), name=f"{artifact.name} tx chain id")
    if tx_chain_id != chain_id:
        raise ReleaseError(f"{artifact.name} transaction belongs to another chain")
    tx_hash = canonical_nonzero_hex(
        entry.get("hash"), name=f"{artifact.name} transaction hash", size=32
    )
    sender = canonical_nonzero_hex(
        transaction.get("from"), name=f"{artifact.name} deployer", size=20
    )
    nonce = parse_quantity(transaction.get("nonce"), name=f"{artifact.name} nonce")
    if transaction.get("to") is not None or parse_quantity(transaction.get("value"), name="deployment value") != 0:
        raise ReleaseError(f"{artifact.name} transaction is not a zero-value creation")
    broadcast_input = parse_hex(transaction.get("input"), name=f"{artifact.name} broadcast input")
    if broadcast_input != artifact.creation_code:
        raise ReleaseError(f"{artifact.name} creation input differs from the reviewed artifact")
    address = canonical_nonzero_hex(
        entry.get("contractAddress"), name=f"{artifact.name} address", size=20
    )
    if address != create_address(sender, nonce, cast_binary):
        raise ReleaseError(f"{artifact.name} address is not sender/nonce CREATE address")

    receipt = require_mapping(rpc.call("eth_getTransactionReceipt", [tx_hash]), name=f"{artifact.name} receipt")
    if parse_quantity(receipt.get("status"), name=f"{artifact.name} status") != 1:
        raise ReleaseError(f"{artifact.name} deployment failed")
    if canonical_hex(receipt.get("transactionHash"), name="receipt tx hash", size=32) != tx_hash:
        raise ReleaseError("receipt transaction hash mismatch")
    if canonical_hex(receipt.get("contractAddress"), name="receipt contract", size=20) != address:
        raise ReleaseError("receipt contract address mismatch")
    if canonical_hex(receipt.get("from"), name="receipt sender", size=20) != sender or receipt.get("to") is not None:
        raise ReleaseError("receipt is not the expected contract creation")
    block_number = parse_quantity(receipt.get("blockNumber"), name="receipt block number")
    block_hash = canonical_hex(receipt.get("blockHash"), name="receipt block hash", size=32)
    if block_number > finalized_number:
        raise ReleaseError(f"{artifact.name} deployment is not finalized")
    if canonical_hex(broadcast_receipt.get("transactionHash"), name="broadcast receipt tx", size=32) != tx_hash:
        raise ReleaseError("broadcast receipt transaction mismatch")
    if canonical_hex(broadcast_receipt.get("contractAddress"), name="broadcast receipt contract", size=20) != address:
        raise ReleaseError("broadcast receipt contract mismatch")
    if parse_quantity(broadcast_receipt.get("blockNumber"), name="broadcast receipt block") != block_number:
        raise ReleaseError("broadcast and RPC receipt block mismatch")
    if canonical_hex(broadcast_receipt.get("blockHash"), name="broadcast receipt block hash", size=32) != block_hash:
        raise ReleaseError("broadcast and RPC receipt block hash mismatch")
    if parse_quantity(broadcast_receipt.get("status"), name="broadcast receipt status") != 1:
        raise ReleaseError("broadcast receipt reports a failed deployment")

    chain_tx = require_mapping(rpc.call("eth_getTransactionByHash", [tx_hash]), name=f"{artifact.name} chain tx")
    if canonical_hex(chain_tx.get("hash"), name="chain transaction hash", size=32) != tx_hash:
        raise ReleaseError("chain transaction hash mismatch")
    if canonical_hex(chain_tx.get("from"), name="chain transaction sender", size=20) != sender:
        raise ReleaseError("chain transaction sender mismatch")
    if chain_tx.get("to") is not None:
        raise ReleaseError("chain transaction is not a creation")
    if parse_quantity(chain_tx.get("nonce"), name="chain transaction nonce") != nonce:
        raise ReleaseError("chain transaction nonce mismatch")
    if parse_quantity(chain_tx.get("chainId"), name="chain transaction chain id") != chain_id:
        raise ReleaseError("chain transaction chain id mismatch")
    if parse_quantity(chain_tx.get("value"), name="chain transaction value") != 0:
        raise ReleaseError("chain transaction creation carries value")
    if parse_quantity(chain_tx.get("blockNumber"), name="chain transaction block") != block_number:
        raise ReleaseError("chain transaction block number mismatch")
    if canonical_hex(chain_tx.get("blockHash"), name="chain transaction block hash", size=32) != block_hash:
        raise ReleaseError("chain transaction block hash mismatch")
    if parse_hex(chain_tx.get("input"), name="chain transaction input") != artifact.creation_code:
        raise ReleaseError("on-chain creation input differs from the reviewed artifact")

    canonical_block = block_record(rpc, block_number, block_hash)
    runtime = parse_hex(
        rpc.call("eth_getCode", [address, "finalized"]), name=f"{artifact.name} finalized runtime"
    )
    if runtime != artifact.runtime_code:
        raise ReleaseError(f"{artifact.name} finalized runtime differs from the reviewed artifact")
    return {
        "abi_entry_count": len(artifact.abi),
        "address": address,
        "artifact": f"out/{Path(artifact.source).name}/{artifact.name}.json",
        "block": canonical_block,
        "creation_code_bytes": len(artifact.creation_code),
        "creation_code_keccak256": keccak256(artifact.creation_code, cast_binary),
        "creation_scheme": "CREATE",
        "deployer": sender,
        "immutable_references": 0,
        "linked_library_references": 0,
        "name": artifact.name,
        "nonce": nonce,
        "role": role,
        "runtime_code_bytes": len(runtime),
        "runtime_code_keccak256": keccak256(runtime, cast_binary),
        "source": artifact.source,
        "transaction_hash": tx_hash,
    }


def build_manifest(
    *,
    project_root: Path,
    artifacts_dir: Path,
    broadcast_path: Path,
    expected_chain_id: int,
    rpc: RpcPort,
    cast_binary: str,
    enforce_dependency_digests: bool = True,
) -> tuple[dict[str, Any], dict[str, str]]:
    if expected_chain_id <= 0 or expected_chain_id > (1 << 64) - 1:
        raise ReleaseError("expected chain id is outside deployment-registry u64")
    broadcast = require_mapping(read_json(broadcast_path), name="broadcast")
    if broadcast.get("libraries") not in ([], None):
        raise ReleaseError("broadcast unexpectedly links libraries")
    if broadcast.get("pending") not in ([], None):
        raise ReleaseError("broadcast still contains pending transactions")
    if broadcast.get("chain") != expected_chain_id:
        raise ReleaseError("broadcast top-level chain id mismatch")
    chain_id = parse_quantity(rpc.call("eth_chainId", []), name="RPC chain id")
    if chain_id != expected_chain_id:
        raise ReleaseError("RPC is pointed at an unexpected chain")

    artifacts: list[tuple[str, Artifact]] = []
    compiler_record: dict[str, Any] | None = None
    remappings: set[str] | None = None
    compiled_source_hashes: dict[str, str] = {}
    for role, contract_name, source in CONTRACTS:
        artifact = load_artifact(artifacts_dir, contract_name, source)
        validate_runtime_interface(artifact)
        compiler, artifact_sources = normalized_compiler(artifact)
        settings = require_mapping(artifact.metadata.get("settings"), name="artifact settings")
        current_remappings = set(require_list(settings.get("remappings", []), name="remappings"))
        if compiler_record is not None and compiler_record != compiler:
            raise ReleaseError("lock contracts were built with different compiler settings")
        if remappings is not None and remappings != current_remappings:
            raise ReleaseError("lock contracts were built with different remappings")
        compiler_record = compiler
        remappings = current_remappings
        merge_source_hashes(compiled_source_hashes, artifact_sources)
        artifacts.append((role, artifact))

    deploy_name, deploy_source = DEPLOY_ARTIFACT
    deploy_artifact = load_artifact(artifacts_dir, deploy_name, deploy_source)
    deploy_compiler, deploy_sources = normalized_compiler(deploy_artifact)
    deploy_settings = require_mapping(deploy_artifact.metadata.get("settings"), name="deploy settings")
    deploy_remappings = set(require_list(deploy_settings.get("remappings", []), name="deploy remappings"))
    if deploy_compiler != compiler_record or deploy_remappings != remappings:
        raise ReleaseError("DeployScript and lock contracts were built with different settings")
    merge_source_hashes(compiled_source_hashes, deploy_sources)
    if compiler_record is None or remappings is None:
        raise ReleaseError("no compiler record")

    dependencies = load_dependency_lock(project_root)
    sources, source_digest, dependency_digests = source_bundle(
        project_root,
        compiled_source_hashes,
        dependencies,
        cast_binary=cast_binary,
        enforce_dependency_digests=enforce_dependency_digests,
    )
    compiler_payload = {
        **compiler_record,
        "dependencies": dependencies,
        "remappings": sorted(remappings),
    }
    compiler_digest = blake2b256(
        b"DOM:EVM-release-compiler:v1", canonical_json_bytes(compiler_payload)
    )
    abi_payload = {artifact.name: artifact.abi for _, artifact in artifacts}
    abi_digest = blake2b256(b"DOM:EVM-release-abi:v1", canonical_json_bytes(abi_payload))

    genesis = block_record(rpc, 0)
    finalized = require_mapping(rpc.call("eth_getBlockByNumber", ["finalized", False]), name="finalized block")
    finalized_number = parse_quantity(finalized.get("number"), name="finalized block number")
    canonical_nonzero_hex(
        finalized.get("hash"), name="finalized block hash", size=32
    )
    parse_quantity(finalized.get("timestamp"), name="finalized block timestamp")
    contract_records = [
        deployment_contract_record(
            rpc=rpc,
            broadcast=broadcast,
            artifact=artifact,
            role=role,
            chain_id=chain_id,
            finalized_number=finalized_number,
            cast_binary=cast_binary,
        )
        for role, artifact in artifacts
    ]
    native = next(value for value in contract_records if value["role"] == "native")
    erc20 = next(value for value in contract_records if value["role"] == "erc20")
    minimum_finalized_block = max(native["block"]["number"], erc20["block"]["number"])
    finality_requirement = {
        "minimum_finalized_block": minimum_finalized_block,
        "required_rpc_tag": "finalized",
    }

    deployment_payload = {
        "abi_digest": abi_digest,
        "chain_id": chain_id,
        "compiler_digest": compiler_digest,
        "contracts": contract_records,
        "finality_requirement": finality_requirement,
        "genesis_hash": genesis["hash"],
        "source_digest": source_digest,
    }
    deployment_digest = blake2b256(
        b"DOM:EVM-release-deployment:v1", canonical_json_bytes(deployment_payload)
    )
    projection = {
        "chain_kind_v1": {
            "erc20_lock_contract": {
                "code_hash": erc20["runtime_code_keccak256"],
                "contract": erc20["address"],
            },
            "evm_chain_id": chain_id,
            "native_code_hash": native["runtime_code_keccak256"],
            "native_lock_contract": native["address"],
        },
        "evm_deployment_v1_release_fields": {
            "abi_digest": abi_digest,
            "compiler_digest": compiler_digest,
            "deployment_digest": deployment_digest,
            "erc20_start_block": erc20["block"]["number"],
            "finalized_tag_required": True,
            "genesis_hash": genesis["hash"],
            "native_start_block": native["block"]["number"],
            "source_digest": source_digest,
        },
        "runtime_policy_fields_not_supplied": [
            "gas_limit_hint",
            "max_fee_per_gas",
            "max_priority_fee_per_gas",
            "page_size",
        ],
    }
    manifest_without_digest = {
        "abi": {
            "blake2b256": abi_digest,
            "contracts": {artifact.name: len(artifact.abi) for _, artifact in artifacts},
            "domain": "DOM:EVM-release-abi:v1",
        },
        "chain": {
            "chain_id": chain_id,
            "finality_requirement": finality_requirement,
            "genesis": genesis,
        },
        "compiler": {
            "blake2b256": compiler_digest,
            "domain": "DOM:EVM-release-compiler:v1",
            **compiler_payload,
        },
        "contracts": contract_records,
        "dependencies": dependencies,
        "deployment_digest": deployment_digest,
        "hash_algorithms": {
            "abi_compiler_source_deployment_manifest": "BLAKE2b-256",
            "creation_and_runtime_code": "Keccak-256",
        },
        "registry_projection": projection,
        "schema": SCHEMA,
        "sources": {
            "blake2b256": source_digest,
            "domain": "DOM:EVM-release-source-bundle:v1",
            "files": sources,
        },
    }
    manifest_digest = blake2b256(
        b"DOM:EVM-release-manifest:v1", canonical_json_bytes(manifest_without_digest)
    )
    manifest = {**manifest_without_digest, "manifest_digest": manifest_digest}
    return manifest, dependency_digests


def write_public_record(path: Path, payload: bytes, *, force: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        raise ReleaseError(f"refusing to overwrite existing manifest: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            os.replace(temp_path, path)
        else:
            try:
                os.link(temp_path, path)
            except FileExistsError as exc:
                raise ReleaseError(f"refusing to overwrite existing manifest: {path}") from exc
            temp_path.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            temp_path.unlink(missing_ok=True)
        finally:
            raise


def rpc_from_environment(variable: str) -> HttpJsonRpc:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", variable):
        raise ReleaseError("RPC environment variable name is invalid")
    url = os.environ.get(variable)
    if not url:
        raise ReleaseError(f"required RPC environment variable is unset: {variable}")
    return HttpJsonRpc(url)


def common_build_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--artifacts-dir", type=Path, default=Path("out"))
    parser.add_argument("--broadcast", type=Path, required=True)
    parser.add_argument("--expected-chain-id", type=int, required=True)
    parser.add_argument("--rpc-url-env", default="DOM_EVM_RELEASE_RPC_URL")
    parser.add_argument("--cast", default="cast")
    parser.add_argument("--forge", default="forge")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect_parser = subparsers.add_parser(
        "inspect-dependencies",
        help="print compiled dependency source digests for updating the reviewed lock",
    )
    inspect_parser.add_argument("--artifacts-dir", type=Path, default=Path("out"))
    inspect_parser.add_argument("--cast", default="cast")
    build_parser = subparsers.add_parser("build", help="build a deployment release manifest")
    common_build_arguments(build_parser)
    build_parser.add_argument("--output", type=Path, required=True)
    build_parser.add_argument("--force", action="store_true")
    verify_parser = subparsers.add_parser("verify", help="rebuild and verify a release manifest")
    common_build_arguments(verify_parser)
    verify_parser.add_argument("--manifest", type=Path, required=True)
    return parser.parse_args(argv)


def inspect_dependencies(
    project_root: Path, artifacts_dir: Path, cast_binary: str = "cast"
) -> dict[str, str]:
    compiled_source_hashes: dict[str, str] = {}
    for _, contract_name, source in CONTRACTS:
        artifact = load_artifact(artifacts_dir, contract_name, source)
        _, hashes = normalized_compiler(artifact)
        merge_source_hashes(compiled_source_hashes, hashes)
    deploy_name, deploy_source = DEPLOY_ARTIFACT
    deploy = load_artifact(artifacts_dir, deploy_name, deploy_source)
    _, hashes = normalized_compiler(deploy)
    merge_source_hashes(compiled_source_hashes, hashes)
    dependencies = load_dependency_lock(project_root)
    _, _, digests = source_bundle(
        project_root,
        compiled_source_hashes,
        dependencies,
        cast_binary=cast_binary,
        enforce_dependency_digests=False,
    )
    return digests


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    project_root = Path(__file__).resolve().parents[1]

    def project_path(path: Path) -> Path:
        return path if path.is_absolute() else project_root / path

    try:
        if args.command == "inspect-dependencies":
            print(
                json.dumps(
                    inspect_dependencies(project_root, project_path(args.artifacts_dir), args.cast),
                    sort_keys=True,
                    indent=2,
                )
            )
            return 0
        rpc = rpc_from_environment(args.rpc_url_env)
        reviewed_artifacts = project_path(args.artifacts_dir)
        with verified_release_artifacts(project_root, reviewed_artifacts, args.forge) as clean_artifacts:
            manifest, _ = build_manifest(
                project_root=project_root,
                artifacts_dir=clean_artifacts,
                broadcast_path=project_path(args.broadcast),
                expected_chain_id=args.expected_chain_id,
                rpc=rpc,
                cast_binary=args.cast,
            )
        encoded = display_json_bytes(manifest)
        if args.command == "build":
            output = project_path(args.output)
            write_public_record(output, encoded, force=args.force)
            print(f"wrote {output}")
            print(f"manifest_digest {manifest['manifest_digest']}")
            return 0
        manifest_path = project_path(args.manifest)
        existing = manifest_path.read_bytes()
        if len(existing) > MAX_JSON_BYTES or existing != encoded:
            raise ReleaseError("manifest is noncanonical, stale or contradicts artifacts/chain")
        print(f"verified {manifest_path}")
        print(f"manifest_digest {manifest['manifest_digest']}")
        return 0
    except (OSError, ReleaseError) as exc:
        print(f"release manifest refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
