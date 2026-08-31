from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Sequence


SCRIPT = Path(__file__).resolve().parents[1] / "release_manifest.py"
SPEC = importlib.util.spec_from_file_location("release_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_manifest = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_manifest
SPEC.loader.exec_module(release_manifest)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = PROJECT_ROOT / "out"
CHAIN_ID = 31_337
SENDER = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"


class FakeRpc:
    def __init__(self, fixtures: dict[tuple[str, str], Any]) -> None:
        self.fixtures = fixtures

    def call(self, method: str, params: Sequence[Any]) -> Any:
        key = (method, json.dumps(list(params), sort_keys=True))
        if key not in self.fixtures:
            raise AssertionError(f"unexpected RPC call: {method} {params!r}")
        return self.fixtures[key]


def fixture() -> tuple[dict[str, Any], FakeRpc]:
    contracts: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    fixtures: dict[tuple[str, str], Any] = {}
    blocks = {
        0: {"number": "0x0", "hash": "0x" + "10" * 32, "timestamp": "0x1"},
        1: {"number": "0x1", "hash": "0x" + "11" * 32, "timestamp": "0x2"},
        2: {"number": "0x2", "hash": "0x" + "12" * 32, "timestamp": "0x3"},
        100: {"number": "0x64", "hash": "0x" + "64" * 32, "timestamp": "0x65"},
    }
    fixtures[("eth_chainId", "[]")] = hex(CHAIN_ID)
    fixtures[("eth_getBlockByNumber", json.dumps(["finalized", False]))] = blocks[100]
    for number, block in blocks.items():
        fixtures[("eth_getBlockByNumber", json.dumps([hex(number), False]))] = block

    for nonce, (_, name, source) in enumerate(release_manifest.CONTRACTS):
        artifact = release_manifest.load_artifact(ARTIFACTS, name, source)
        tx_hash = "0x" + bytes([0xA0 + nonce]).hex() * 32
        address = release_manifest.create_address(SENDER, nonce, "cast")
        block = blocks[nonce + 1]
        tx = {
            "from": SENDER,
            "to": None,
            "nonce": hex(nonce),
            "chainId": hex(CHAIN_ID),
            "value": "0x0",
            "input": "0x" + artifact.creation_code.hex(),
        }
        receipt = {
            "status": "0x1",
            "transactionHash": tx_hash,
            "blockHash": block["hash"],
            "blockNumber": block["number"],
            "contractAddress": address,
            "from": SENDER,
            "to": None,
        }
        contracts.append(
            {
                "hash": tx_hash,
                "transactionType": "CREATE",
                "contractName": name,
                "contractAddress": address,
                "function": None,
                "arguments": None,
                "transaction": tx,
                "additionalContracts": [],
            }
        )
        receipts.append(receipt)
        fixtures[("eth_getTransactionReceipt", json.dumps([tx_hash]))] = receipt
        fixtures[("eth_getTransactionByHash", json.dumps([tx_hash]))] = {
            "hash": tx_hash,
            "blockHash": block["hash"],
            "blockNumber": block["number"],
            **tx,
        }
        fixtures[("eth_getCode", json.dumps([address, "finalized"]))] = "0x" + artifact.runtime_code.hex()

    broadcast = {
        "transactions": contracts,
        "receipts": receipts,
        "libraries": [],
        "pending": [],
        "chain": CHAIN_ID,
    }
    return broadcast, FakeRpc(fixtures)


def build(broadcast: dict[str, Any], rpc: FakeRpc) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "run.json"
        path.write_text(json.dumps(broadcast), encoding="utf-8")
        manifest, _ = release_manifest.build_manifest(
            project_root=PROJECT_ROOT,
            artifacts_dir=ARTIFACTS,
            broadcast_path=path,
            expected_chain_id=CHAIN_ID,
            rpc=rpc,
            cast_binary="cast",
        )
    return manifest


class ReleaseManifestTests(unittest.TestCase):
    def test_manifest_maps_exactly_to_registry_release_fields(self) -> None:
        broadcast, rpc = fixture()
        manifest = build(broadcast, rpc)

        self.assertEqual(manifest["schema"], release_manifest.SCHEMA)
        self.assertRegex(manifest["manifest_digest"], r"^0x[0-9a-f]{64}$")
        projection = manifest["registry_projection"]
        kind = projection["chain_kind_v1"]
        deployment = projection["evm_deployment_v1_release_fields"]
        self.assertEqual(kind["evm_chain_id"], CHAIN_ID)
        self.assertEqual(kind["native_lock_contract"], manifest["contracts"][0]["address"])
        self.assertEqual(
            kind["native_code_hash"], manifest["contracts"][0]["runtime_code_keccak256"]
        )
        self.assertEqual(deployment["native_start_block"], 1)
        self.assertEqual(deployment["erc20_start_block"], 2)
        self.assertIs(deployment["finalized_tag_required"], True)
        self.assertEqual(deployment["deployment_digest"], manifest["deployment_digest"])
        self.assertEqual(
            projection["runtime_policy_fields_not_supplied"],
            [
                "gas_limit_hint",
                "max_fee_per_gas",
                "max_priority_fee_per_gas",
                "page_size",
            ],
        )

    def test_same_facts_produce_byte_identical_manifest(self) -> None:
        first_broadcast, first_rpc = fixture()
        second_broadcast, second_rpc = fixture()
        second_rpc.fixtures[("eth_getBlockByNumber", json.dumps(["finalized", False]))] = {
            "number": "0xc8",
            "hash": "0x" + "65" * 32,
            "timestamp": "0xc9",
        }
        first = build(first_broadcast, first_rpc)
        second = build(second_broadcast, second_rpc)
        self.assertEqual(release_manifest.display_json_bytes(first), release_manifest.display_json_bytes(second))

    def test_refuses_runtime_that_differs_from_reviewed_artifact(self) -> None:
        broadcast, rpc = fixture()
        address = broadcast["transactions"][0]["contractAddress"].lower()
        rpc.fixtures[("eth_getCode", json.dumps([address, "finalized"]))] = "0x6000"
        with self.assertRaisesRegex(release_manifest.ReleaseError, "finalized runtime differs"):
            build(broadcast, rpc)

    def test_refuses_creation_address_not_derived_from_sender_and_nonce(self) -> None:
        broadcast, rpc = fixture()
        broadcast["transactions"][0]["contractAddress"] = "0x" + "ff" * 20
        with self.assertRaisesRegex(release_manifest.ReleaseError, "sender/nonce CREATE address"):
            build(broadcast, rpc)

    def test_refuses_deployment_above_finalized_anchor(self) -> None:
        broadcast, rpc = fixture()
        rpc.fixtures[("eth_getBlockByNumber", json.dumps(["finalized", False]))] = {
            "number": "0x1",
            "hash": "0x" + "11" * 32,
            "timestamp": "0x2",
        }
        with self.assertRaisesRegex(release_manifest.ReleaseError, "deployment is not finalized"):
            build(broadcast, rpc)

    def test_refuses_rpc_on_another_chain(self) -> None:
        broadcast, rpc = fixture()
        rpc.fixtures[("eth_chainId", "[]")] = "0x1"
        with self.assertRaisesRegex(release_manifest.ReleaseError, "unexpected chain"):
            build(broadcast, rpc)

    def test_refuses_non_create_or_constructor_arguments(self) -> None:
        broadcast, rpc = fixture()
        broadcast["transactions"][0]["transactionType"] = "CREATE2"
        with self.assertRaisesRegex(release_manifest.ReleaseError, "constructor-argument-free CREATE"):
            build(broadcast, rpc)

    def test_create_address_matches_anvil_known_deployments(self) -> None:
        self.assertEqual(
            release_manifest.create_address(SENDER, 0, "cast"),
            "0x5fbdb2315678afecb367f032d93f642f64180aa3",
        )
        self.assertEqual(
            release_manifest.create_address(SENDER, 1, "cast"),
            "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
        )

    def test_display_encoding_is_strictly_canonical(self) -> None:
        broadcast, rpc = fixture()
        manifest = build(broadcast, rpc)
        encoded = release_manifest.display_json_bytes(manifest)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(encoded, release_manifest.display_json_bytes(json.loads(encoded)))
        self.assertNotEqual(encoded, release_manifest.canonical_json_bytes(manifest))

    def test_dependency_lock_matches_all_compiled_dependency_sources(self) -> None:
        digests = release_manifest.inspect_dependencies(PROJECT_ROOT, ARTIFACTS)
        self.assertEqual(
            digests,
            {
                "forge-std": "0xf645cecd33af83eda8bd738626f82367db7fded6b00c6d48c69e9ebf19b9a8b1",
                "openzeppelin-contracts": "0xc95ba50657b4de83adc87e5e0067631b3859118cae7e3d61a4657704c3915c76",
            },
        )

    def test_refuses_source_that_no_longer_matches_compiler_metadata(self) -> None:
        dependencies = release_manifest.load_dependency_lock(PROJECT_ROOT)
        with self.assertRaisesRegex(release_manifest.ReleaseError, "does not match source"):
            release_manifest.source_bundle(
                PROJECT_ROOT,
                {"src/ConditionLockV2.sol": "0x" + "ff" * 32},
                dependencies,
                cast_binary="cast",
                enforce_dependency_digests=False,
            )

    def test_clean_recompile_refuses_a_tampered_reviewed_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            reviewed = Path(directory) / "out"
            for _, name, source in release_manifest.CONTRACTS:
                target = release_manifest.artifact_path(reviewed, source, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(release_manifest.artifact_path(ARTIFACTS, source, name), target)
            deploy_name, deploy_source = release_manifest.DEPLOY_ARTIFACT
            deploy_target = release_manifest.artifact_path(reviewed, deploy_source, deploy_name)
            deploy_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(release_manifest.artifact_path(ARTIFACTS, deploy_source, deploy_name), deploy_target)

            native_path = release_manifest.artifact_path(
                reviewed, "src/ConditionLockV2.sol", "ConditionLockV2"
            )
            native = json.loads(native_path.read_text(encoding="utf-8"))
            native["bytecode"]["object"] = "0x6000"
            native_path.write_text(json.dumps(native), encoding="utf-8")

            with self.assertRaisesRegex(release_manifest.ReleaseError, "clean source compilation"):
                with release_manifest.verified_release_artifacts(PROJECT_ROOT, reviewed, "forge"):
                    self.fail("tampered artifact unexpectedly passed")

    def test_json_inputs_reject_duplicate_keys_and_non_finite_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_bytes(b'{"chain":1,"chain":2}')
            with self.assertRaisesRegex(release_manifest.ReleaseError, "duplicate key"):
                release_manifest.read_json(path)
            path.write_bytes(b'{"chain":NaN}')
            with self.assertRaisesRegex(release_manifest.ReleaseError, "non-finite"):
                release_manifest.read_json(path)

    def test_public_record_refuses_overwrite_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.json"
            release_manifest.write_public_record(path, b"first\n", force=False)
            with self.assertRaisesRegex(release_manifest.ReleaseError, "refusing to overwrite"):
                release_manifest.write_public_record(path, b"second\n", force=False)
            self.assertEqual(path.read_bytes(), b"first\n")


if __name__ == "__main__":
    unittest.main()
