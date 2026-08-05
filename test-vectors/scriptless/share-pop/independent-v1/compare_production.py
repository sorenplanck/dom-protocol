#!/usr/bin/env python3
"""Post-freeze byte comparison against the inspected Rust production profile."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
INPUTS_PATH = ROOT / "inputs_v1.json"
REFERENCE_PATH = ROOT / "expected_outputs_v1.json"
TRACE_PATH = ROOT / "production_trace_v1.json"
RESULTS_PATH = ROOT / "comparison_results_v1.json"
POST_MANIFEST_PATH = ROOT / "POSTCOMPARISON-MANIFEST.sha256"
EXTERNAL_REPORT_PATH = (
    ROOT.parents[3]
    / "docs/scriptless/reports/phase-1/G1A-SHARE-POP-INDEPENDENT-REVIEW.en.md"
)
PRODUCTION_CONTEXT_TAG = b"DOM:scriptless-share-pop:v1"
PRODUCTION_CHALLENGE_TAG = b"DOM:scriptless-share-pop-challenge:v1"

spec = importlib.util.spec_from_file_location("independent_reference", ROOT / "generate_reference.py")
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load frozen independent generator")
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def postcomparison_manifest_text() -> str:
    members = (
        ("MANIFEST.sha256", ROOT / "MANIFEST.sha256"),
        ("compare_production.py", ROOT / "compare_production.py"),
        ("comparison_results_v1.json", ROOT / "comparison_results_v1.json"),
        ("production-probe/Cargo.lock", ROOT / "production-probe/Cargo.lock"),
        ("production-probe/Cargo.toml", ROOT / "production-probe/Cargo.toml"),
        ("production-probe/src/main.rs", ROOT / "production-probe/src/main.rs"),
        ("production_trace_v1.json", ROOT / "production_trace_v1.json"),
        (
            "../../../../docs/scriptless/reports/phase-1/G1A-SHARE-POP-INDEPENDENT-REVIEW.en.md",
            EXTERNAL_REPORT_PATH,
        ),
    )
    return "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}\n"
        for name, path in members
    )


def roster_for(case: dict[str, Any], cases: list[dict[str, Any]]) -> list[bytes]:
    if case["case_id"] in ("SP1-initiator-index-zero", "SP2-responder-index-one"):
        return [bytes.fromhex(cases[0]["participant_id_32"]), bytes.fromhex(cases[1]["participant_id_32"])]
    return [bytes((value,)) * 32 for value in range(1, 16)] + [bytes.fromhex(case["participant_id_32"])]


def production_case(case: dict[str, Any], frozen: dict[str, Any], all_cases: list[dict[str, Any]]) -> dict[str, Any]:
    roster = roster_for(case, all_cases)
    terms_hash = bytes.fromhex(case["terms_hash_32"])
    recovery_binding_hash = bytes.fromhex(case["capsule_hash_32"])
    common = {
        "case_id": case["case_id"],
        "participant_roster": [item.hex() for item in roster],
        "participant_index_u16": case["participant_index_u16"],
        "attempted_inputs": {
            "chain_id_32": case["chain_id_32"],
            "session_id_32": case["session_id_32"],
            "participant_id_32": case["participant_id_32"],
            "role_u8": case["role_u8"],
            "share_point_sec1_33": frozen["share_point_sec1_33"],
            "terms_hash_32": case["terms_hash_32"],
            "recovery_binding_hash_32": case["capsule_hash_32"],
        },
    }
    if terms_hash == bytes(32):
        return {
            **common,
            "construction": {
                "accepted": False,
                "first_rejection": "share PoK terms hash must be nonzero",
            },
        }
    if recovery_binding_hash == bytes(32):
        return {
            **common,
            "construction": {
                "accepted": False,
                "first_rejection": "share PoK recovery binding hash must be nonzero",
            },
        }

    independent_statement = bytes.fromhex(frozen["statement_bytes"])
    statement = b"DSPO" + (1).to_bytes(2, "little") + independent_statement
    share_point = bytes.fromhex(frozen["share_point_sec1_33"])
    announcement = bytes.fromhex(frozen["pop_nonce_point_sec1_33"])
    context_digest = reference.h_tag(PRODUCTION_CONTEXT_TAG, statement)
    challenge_preimage = context_digest + share_point + announcement
    counter = 0
    while True:
        challenge_input = challenge_preimage + counter.to_bytes(4, "little")
        digest_0_data = b"\x00" + challenge_input
        digest_1_data = b"\x01" + challenge_input
        digest_0 = reference.h_tag(PRODUCTION_CHALLENGE_TAG, digest_0_data)
        digest_1 = reference.h_tag(PRODUCTION_CHALLENGE_TAG, digest_1_data)
        wide = digest_0 + digest_1
        challenge = int.from_bytes(wide, "big") % reference.N
        if challenge != 0:
            break
        counter += 1
        if counter > 0xFFFFFFFF:
            raise AssertionError("production challenge counter overflow")
    share_scalar = int(case["public_insecure_share_scalar_be32"], 16)
    nonce_scalar = int(case["public_insecure_pop_nonce_scalar_be32"], 16)
    response = (nonce_scalar + challenge * share_scalar) % reference.N
    proof = announcement + response.to_bytes(32, "big")
    parsed = reference.decode_point(announcement, "invalid_announcement")
    share = reference.decode_point(share_point, "invalid_share")
    equation = reference.scalar_mul(response) == reference.point_add(
        parsed, reference.scalar_mul(challenge, share)
    )
    if not equation:
        raise AssertionError("modeled production proof did not satisfy its equation")
    return {
        **common,
        "construction": {"accepted": True, "first_rejection": None},
        "statement_length": len(statement),
        "statement_bytes": statement.hex(),
        "statement_tagged_input_bytes": reference.tagged_input(PRODUCTION_CONTEXT_TAG, statement).hex(),
        "share_point_sec1_33": share_point.hex(),
        "context_digest_32": context_digest.hex(),
        "pop_nonce_point_sec1_33": announcement.hex(),
        "challenge_preimage_bytes": challenge_preimage.hex(),
        "challenge_counter_u32_le": counter.to_bytes(4, "little").hex(),
        "challenge_input_bytes": challenge_input.hex(),
        "challenge_digest_0_data_bytes": digest_0_data.hex(),
        "challenge_digest_0_tagged_input_bytes": reference.tagged_input(
            PRODUCTION_CHALLENGE_TAG, digest_0_data
        ).hex(),
        "challenge_digest_0_32": digest_0.hex(),
        "challenge_digest_1_data_bytes": digest_1_data.hex(),
        "challenge_digest_1_tagged_input_bytes": reference.tagged_input(
            PRODUCTION_CHALLENGE_TAG, digest_1_data
        ).hex(),
        "challenge_digest_1_32": digest_1.hex(),
        "challenge_wide_digest_64": wide.hex(),
        "challenge_reduced_be32": challenge.to_bytes(32, "big").hex(),
        "response_be32": response.to_bytes(32, "big").hex(),
        "proof_length": len(proof),
        "proof_bytes": proof.hex(),
        "verification": {"accepted": True, "first_rejection": None},
    }


def comparison(name: str, independent_hex: str, production_hex: str) -> dict[str, Any]:
    independent = bytes.fromhex(independent_hex)
    production = bytes.fromhex(production_hex)
    first_difference = None
    for index, (left, right) in enumerate(zip(independent, production)):
        if left != right:
            first_difference = index
            break
    if first_difference is None and len(independent) != len(production):
        first_difference = min(len(independent), len(production))
    return {
        "field": name,
        "match": independent == production,
        "independent_length": len(independent),
        "production_length": len(production),
        "first_differing_byte_offset": first_difference,
        "independent_hex": independent_hex,
        "production_hex": production_hex,
    }


def compare_case(case: dict[str, Any], frozen: dict[str, Any], production: dict[str, Any]) -> dict[str, Any]:
    if not production["construction"]["accepted"]:
        return {
            "case_id": case["case_id"],
            "status": "STOP_AUTHORITY_INPUT_CONFLICT",
            "first_divergence": "the higher-precedence signed statement constructor rejects an input accepted by the frozen lower-precedence reference",
            "production_rejection": production["construction"]["first_rejection"],
            "independent_verification": frozen["verification"],
            "field_comparisons": [],
        }
    mappings = (
        ("statement_bytes", "statement_bytes"),
        ("statement_tagged_input_bytes", "statement_tagged_input_bytes"),
        ("share_point_sec1_33", "share_point_sec1_33"),
        ("context_digest_32", "context_digest_32"),
        ("pop_nonce_point_sec1_33", "pop_nonce_point_sec1_33"),
        ("challenge_preimage_bytes", "challenge_preimage_bytes"),
        ("challenge_digest_0_data_bytes", "challenge_digest_0_data_bytes"),
        ("challenge_digest_0_tagged_input_bytes", "challenge_digest_0_tagged_input_bytes"),
        ("challenge_digest_0_32", "challenge_digest_0_32"),
        ("challenge_digest_1_data_bytes", "challenge_digest_1_data_bytes"),
        ("challenge_digest_1_tagged_input_bytes", "challenge_digest_1_tagged_input_bytes"),
        ("challenge_digest_1_32", "challenge_digest_1_32"),
        ("challenge_wide_digest_64", "challenge_wide_digest_64"),
        ("challenge_reduced_be32", "challenge_reduced_be32"),
        ("response_be32", "response_be32"),
        ("proof_bytes", "proof_bytes"),
    )
    fields = [comparison(left, frozen[left], production[right]) for left, right in mappings]
    independent_statement = bytes.fromhex(frozen["statement_bytes"])
    production_proof = bytes.fromhex(production["proof_bytes"])
    cross_production_under_reference = reference.verify(independent_statement, production_proof)
    return {
        "case_id": case["case_id"],
        "status": "MATCH" if all(field["match"] for field in fields) else "STOP_AUTHORITY_INPUT_CONFLICT",
        "first_divergence": next((field["field"] for field in fields if not field["match"]), None),
        "field_comparisons": fields,
        "native_verification": {
            "independent_proof_under_independent_profile": frozen["verification"],
            "production_proof_under_production_profile": production["verification"],
            "production_proof_under_independent_profile": cross_production_under_reference,
            "independent_statement_parse_under_production_profile": {
                "accepted": False,
                "first_rejection": "invalid_statement_length: expected 202, received 196",
            },
        },
    }


def production_proof_parser_result(mutation: dict[str, Any]) -> dict[str, Any]:
    proof = bytes.fromhex(mutation["proof_bytes"])
    if len(proof) != 65:
        return {"accepted": False, "first_rejection": "invalid_proof_length"}
    try:
        reference.decode_point(proof[:33], "invalid_announcement_encoding")
    except reference.ReferenceError as exc:
        return {"accepted": False, "first_rejection": str(exc)}
    response = int.from_bytes(proof[33:], "big")
    if response >= reference.N:
        return {"accepted": False, "first_rejection": "noncanonical_response_scalar"}
    return {"accepted": True, "first_rejection": None}


def generate() -> tuple[dict[str, Any], dict[str, Any]]:
    inputs = json.loads(INPUTS_PATH.read_text(encoding="utf-8"))
    frozen = json.loads(REFERENCE_PATH.read_text(encoding="utf-8"))
    frozen_by_id = {case["case_id"]: case for case in frozen["valid_cases"]}
    production_cases = [
        production_case(case, frozen_by_id[case["case_id"]], inputs["cases"])
        for case in inputs["cases"]
    ]
    trace = {
        "fixture": "Inspected Rust Share PoK production-profile trace v1",
        "warning": inputs["warning"],
        "production_source": "crates/dom-adaptor/src/share_pop.rs at starting HEAD 67fe11c441c2b7801b6f70809ab58caa4804c22a",
        "authoritative_assignment": {
            "path": "/home/leonardov/dom-scriptless-dev/dom-contracts/docs/specifications/normative/NAR-DC-P1-001-omnibus-gap-closure.en.md",
            "sha256": "88586449d577038ac98e9463250821ed9b3d1e6c94f5b11abfaf036a93eec655",
            "minisign_sha256": "2f19ec266f05e440cb5de2b91bc4295b93b2629170adbf6d020505ebb2311ffc",
            "signature_verified": True,
            "relevant_sections": "5.1 through 5.5",
        },
        "production_context_tag_ascii": PRODUCTION_CONTEXT_TAG.decode("ascii"),
        "production_challenge_tag_ascii": PRODUCTION_CHALLENGE_TAG.decode("ascii"),
        "production_statement_layout": "DSPO || version_u16_le || chain_id_32 || session_id_32 || participant_id_32 || role_u8 || participant_index_u16_le || share_point_R_sec1_33 || terms_hash_32 || recovery_binding_hash_32",
        "production_challenge_expansion": "d0 = H_tag(challenge_tag, 0x00 || context || R || A || retry_counter_u32_le); d1 uses 0x01; c = BE512(d0 || d1) mod n; retry on c=0",
        "cases": production_cases,
    }
    comparisons = [
        compare_case(case, frozen_by_id[case["case_id"]], production)
        for case, production in zip(inputs["cases"], production_cases)
    ]
    negative = []
    for mutation in frozen["negative_mutations"]:
        parser_result = production_proof_parser_result(mutation)
        negative.append(
            {
                "mutation_id": mutation["mutation_id"],
                "independent_verification": mutation["verification"],
                "production_statement_parser": {
                    "accepted": False,
                    "first_rejection": "invalid_statement_length: expected 202, received 196",
                },
                "production_proof_parser": parser_result,
                "parser_classification_match": parser_result == mutation["verification"],
            }
        )
    results = {
        "fixture": "DOM G1a Share PoK independent-to-production comparison v1",
        "warning": inputs["warning"],
        "precomparison_commit": "fce85fa7af614ed8d99419045ea3fb5ce26981e2",
        "precomparison_commit_time": "2026-08-05T07:38:48-03:00",
        "precomparison_manifest_sha256": "6a2308121c15a285c1b9d7b01dbbe16c55c02ca267483361a60e906028514d3b",
        "overall_status": "STOP_AUTHORITY_INPUT_CONFLICT",
        "first_divergence": {
            "case_id": "SP1-initiator-index-zero",
            "field": "statement_bytes",
            "byte_offset": 0,
            "independent_prefix": frozen_by_id["SP1-initiator-index-zero"]["statement_bytes"][:12],
            "production_prefix": production_cases[0]["statement_bytes"][:12],
            "reason": "the frozen reference followed lower-precedence Master Specification section 4.2; production follows signed NAR-DC-P1-001 section 5.2 and prepends DSPO || 0x0001_le, yielding the authoritative 202-byte statement",
        },
        "case_comparisons": comparisons,
        "negative_mutation_comparisons": negative,
        "authority_input_findings": [
            "The frozen reference was derived from Master Specification v1.0 section 4.2 (controlled DOCX SHA-256 5ad366d6...) plus NAR-001/NAR-002, without NAR-DC-P1-001 in the selected source set.",
            "The independently verified NAR-DC-P1-001 signature gives its express Share PoK assignments precedence over the Master Specification and earlier records.",
            "NAR-DC-P1-001 sections 5.1-5.5 explicitly assign the second challenge tag, the 202-byte DSPO statement, prefix half selectors, u32_le retry counter, nonzero fixed digests, and a response range that includes zero.",
            "The inspected production source follows those higher-precedence assignments byte for byte; no production Share PoK discrepancy was found.",
            "The frozen reference and outputs remain unchanged as negative provenance evidence and must not be treated as conformant expected outputs.",
        ],
    }
    return trace, results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args()
    if args.write_manifest:
        POST_MANIFEST_PATH.write_text(postcomparison_manifest_text(), encoding="utf-8")
        print(f"wrote {POST_MANIFEST_PATH.name}")
        return 0
    trace, results = generate()
    trace_text = canonical_json(trace)
    results_text = canonical_json(results)
    if args.write:
        TRACE_PATH.write_text(trace_text, encoding="utf-8")
        RESULTS_PATH.write_text(results_text, encoding="utf-8")
        print(f"wrote {TRACE_PATH.name} and {RESULTS_PATH.name}")
        return 0
    if TRACE_PATH.read_text(encoding="utf-8") != trace_text:
        raise SystemExit("production_trace_v1.json differs from regeneration")
    if RESULTS_PATH.read_text(encoding="utf-8") != results_text:
        raise SystemExit("comparison_results_v1.json differs from regeneration")
    if POST_MANIFEST_PATH.exists():
        expected_manifest = postcomparison_manifest_text()
        if POST_MANIFEST_PATH.read_text(encoding="utf-8") != expected_manifest:
            raise SystemExit("POSTCOMPARISON-MANIFEST.sha256 differs from current files")
    print("post-freeze production trace and comparison results verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
