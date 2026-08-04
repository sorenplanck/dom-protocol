#!/usr/bin/env python3
"""Validate the unsigned supplemental two-party input fixture without outputs."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import generate_reference as reference


class SupplementalInputError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def reject(code: str, detail: str) -> None:
    raise SupplementalInputError(code, detail)


BASE_FIELDS = {
    "name",
    "expected",
    "context_version_u16_le",
    "chain_id_32",
    "session_id_32",
    "purpose_u8",
    "signing_phase_u16_le",
    "template_hash_32",
    "message_digest_32",
    "transcript_hash_32",
    "participant_count_u16_le",
    "participant_public_keys_sec1",
    "binding_participant_order_u16_le",
    "aggregate_excess_public_keys_sec1",
    "participant_0_index_u16_le",
    "participant_0_direction_u8",
    "participant_0_retry_counter_u64_le",
    "participant_0_signing_share_be32",
    "participant_0_signing_public_key_sec1",
    "participant_0_aux_rand_32",
    "participant_1_index_u16_le",
    "participant_1_direction_u8",
    "participant_1_retry_counter_u64_le",
    "participant_1_signing_share_be32",
    "participant_1_signing_public_key_sec1",
    "participant_1_aux_rand_32",
    "adaptor_presence_u8",
    "adaptor_secret_be32",
    "adaptor_point_sec1",
    "kernel_challenge_chain_id_32",
    "kernel_challenge_message_digest_32",
}

EXPECTED_NEGATIVE_CODES = {
    "SN1-purpose-refund-with-adaptor": "unexpected_adaptor",
    "SN2-purpose-sponsor-strict-phase1": "sponsor_policy",
    "SN3-purpose-unknown": "unknown_purpose",
    "SN4-claim-missing-adaptor": "claim_requires_adaptor",
    "SN5-adaptor-invalid-prefix": "invalid_point",
    "SN6-adaptor-secret-point-mismatch": "adaptor_secret_mismatch",
    "SN7-roster-reversed": "unsorted_participant_roster",
    "SN8-roster-duplicate": "duplicate_participant",
    "SN9-participant-0-index-mismatch": "signer_roster_mismatch",
    "SN10-participant-1-index-out-of-range": "participant_index_out_of_range",
    "SN11-participant-1-scalar-zero": "invalid_signing_scalar",
    "SN12-participant-1-scalar-equal-order": "invalid_signing_scalar",
    "SN13-participant-1-secret-public-mismatch": "signing_key_mismatch",
    "SN14-two-initiators": "incomplete_role_assignment",
    "SN15-chain-zero": "untrusted_chain_id",
    "SN16-kernel-chain-diverges-from-context": "kernel_chain_mismatch",
    "SN17-kernel-message-diverges-from-context": "kernel_message_mismatch",
    "SN18-base-phase-outside-signing-subregistry": "unknown_signing_phase",
    "SN19-participant-0-aux-wrong-length": "invalid_length",
    "SN20-aggregate-excess-input-order-diverges": "aggregate_excess_order_mismatch",
}


def participant_case(case: dict[str, Any], participant: int) -> dict[str, Any]:
    return {
        "context_version_u16_le": case["context_version_u16_le"],
        "chain_id_32": case["chain_id_32"],
        "session_id_32": case["session_id_32"],
        "purpose_u8": case["purpose_u8"],
        "direction_u8": case[f"participant_{participant}_direction_u8"],
        "signing_phase_u16_le": case["signing_phase_u16_le"],
        "template_hash_32": case["template_hash_32"],
        "message_digest_32": case["message_digest_32"],
        "transcript_hash_32": case["transcript_hash_32"],
        "retry_counter_u64_le": case[f"participant_{participant}_retry_counter_u64_le"],
        "participant_count_u16_le": case["participant_count_u16_le"],
        "participant_public_keys_sec1": case["participant_public_keys_sec1"],
        "participant_index_u16_le": case[f"participant_{participant}_index_u16_le"],
        "signing_share_be32": case[f"participant_{participant}_signing_share_be32"],
        "signing_public_key_sec1": case[f"participant_{participant}_signing_public_key_sec1"],
        "adaptor_presence_u8": case["adaptor_presence_u8"],
        "adaptor_secret_be32": case["adaptor_secret_be32"],
        "adaptor_point_sec1": case["adaptor_point_sec1"],
        "aux_rand_32": case[f"participant_{participant}_aux_rand_32"],
    }


def validate_case(case: dict[str, Any]) -> None:
    if set(case) != BASE_FIELDS:
        reject("invalid_case_fields", "base or expanded case has missing or unknown fields")

    for participant in (0, 1):
        context = participant_case(case, participant)
        reference.validate_and_encode(context)
        reference.decode_hex(context["aux_rand_32"], f"participant_{participant}_aux_rand_32", 32)

    directions = {
        int(case["participant_0_direction_u8"], 16),
        int(case["participant_1_direction_u8"], 16),
    }
    if directions != {0x01, 0x02}:
        reject("incomplete_role_assignment", "the two-party fixture requires exactly one Initiator and one Responder")

    count = int.from_bytes(reference.decode_hex(case["participant_count_u16_le"], "participant_count_u16_le", 2), "little")
    expected_order = [index.to_bytes(2, "little").hex() for index in range(count)]
    if case["binding_participant_order_u16_le"] != expected_order:
        reject("binding_order_mismatch", "binding order must enumerate participant indices exactly once")

    roster = case["participant_public_keys_sec1"]
    if case["aggregate_excess_public_keys_sec1"] != roster:
        reject("aggregate_excess_order_mismatch", "aggregate excess inputs must equal the canonical roster order")
    aggregate = None
    for index, encoded in enumerate(case["aggregate_excess_public_keys_sec1"]):
        point = reference.decode_point(
            reference.decode_hex(encoded, f"aggregate_excess_public_keys_sec1[{index}]", 33),
            f"aggregate_excess_public_keys_sec1[{index}]",
        )
        aggregate = reference.point_add(aggregate, point)
    if aggregate is None:
        reject("aggregate_excess_identity", "aggregate excess must be nonidentity")

    chain_id = reference.decode_hex(case["chain_id_32"], "chain_id_32", 32)
    kernel_chain = reference.decode_hex(case["kernel_challenge_chain_id_32"], "kernel_challenge_chain_id_32", 32)
    if kernel_chain != chain_id:
        reject("kernel_chain_mismatch", "kernel challenge chain ID differs from canonical context")
    message = reference.decode_hex(case["message_digest_32"], "message_digest_32", 32)
    kernel_message = reference.decode_hex(
        case["kernel_challenge_message_digest_32"], "kernel_challenge_message_digest_32", 32
    )
    if kernel_message != message:
        reject("kernel_message_mismatch", "kernel challenge message differs from canonical context")


def expand(base: dict[str, Any], mutation: dict[str, Any]) -> dict[str, Any]:
    if set(mutation) != {"name", "replace", "expected"}:
        raise ValueError(f"mutation {mutation.get('name')} has missing or unknown fields")
    replacements = mutation["replace"]
    if not isinstance(replacements, dict):
        raise ValueError("replace must be an object")
    expanded = copy.deepcopy(base)
    for field, value in replacements.items():
        if field not in expanded:
            raise ValueError(f"mutation {mutation['name']} replaces unknown field {field}")
        expanded[field] = copy.deepcopy(value)
    expanded["name"] = mutation["name"]
    expanded["expected"] = mutation["expected"]
    return expanded


def main() -> int:
    script_path = Path(__file__).resolve()
    repo_root = script_path.parents[5]
    fixture_path = repo_root / "test-vectors/scriptless/two-nonce/kat_two_party_adaptor_inputs_v1.en.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    if fixture["status"] != "FINAL CANDIDATE — EFFECTIVE ONLY AFTER VALID DETACHED RATIFICATION":
        raise ValueError("fixture must remain an unsigned final candidate")
    if Path(str(fixture_path) + ".minisig").exists():
        raise ValueError("candidate validator refuses an unexpected signature sidecar")
    if fixture["curve"]["order_n_be32"] != reference.N.to_bytes(32, "big").hex():
        raise ValueError("fixture group order differs from secp256k1")

    base = fixture["base_case"]
    validate_case(base)
    for mutation in fixture["accepted_mutations"]:
        validate_case(expand(base, mutation))

    observed_rejections: list[tuple[str, str]] = []
    for mutation in fixture["rejected_mutations"]:
        expanded = expand(base, mutation)
        try:
            validate_case(expanded)
        except (reference.ReferenceError, SupplementalInputError) as error:
            expected = EXPECTED_NEGATIVE_CODES.get(mutation["name"])
            if expected is None or error.code != expected:
                raise AssertionError(
                    f"{mutation['name']} rejected as {error.code}, expected {expected}"
                ) from error
            observed_rejections.append((mutation["name"], error.code))
        else:
            raise AssertionError(f"negative case {mutation['name']} was accepted")

    print(
        f"supplemental input fixture valid: 1 base + {len(fixture['accepted_mutations'])} "
        f"accepted mutations; {len(observed_rejections)} rejected mutations"
    )
    print("no expected cryptographic outputs generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
