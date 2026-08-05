#!/usr/bin/env python3
"""Generate independent, byte-complete two-party Scriptless V1 vectors.

The implementation is evidence-only. It uses the Python standard library and
the bounded pure-Python secp256k1 boundary in generate_reference.py. It imports
no DOM Rust crate and no production G1a implementation.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

import generate_reference as ref
import validate_supplemental_inputs as supplemental


TAG_PARTICIPANT = "DOM:scriptless-participant:v1"
TAG_COMMITMENT = "DOM:scriptless-nonce-commit:v1"
TAG_BINDING = "DOM:scriptless-sig-nonce-bind:v1"
TAG_CHALLENGE = "DOM:kernel-sig:v1"

NAR_002_SHA256 = "b726c2e576833f843d0065a1e823e649ab9e7e28fd9cfedb0e6e06e6b1be87f5"
NAR_002_SIGNATURE_SHA256 = "fd1f1155e48190913e0fae10770afcdac5bf01e4bc410a663327fce3881c64c2"
SUPPLEMENTAL_INPUT_SHA256 = "5e5063e819e7d64514039905c3c9fed0cb98c39f36c370fdb4c413751a08fac9"
SUPPLEMENTAL_SIGNATURE_SHA256 = "2f0fc550cda61ffb9377f1ce0055fbe9196bc9bcdf0406eb868cda89ce8df7ed"

CHAIN_ID = bytes.fromhex("aa" * 32)
ROSTER = [
    bytes.fromhex("02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f"),
    bytes.fromhex("03f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b"),
]
SHARES = [int.from_bytes(bytes.fromhex("07" * 32), "big"), int.from_bytes(bytes.fromhex("08" * 32), "big")]
AUX = [bytes.fromhex("09" * 32), bytes.fromhex("0a" * 32)]
DIRECTIONS = [bytes.fromhex("01"), bytes.fromhex("02")]
IDENTITY_KEYS = [
    bytes.fromhex("03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb"),
    bytes.fromhex("02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e"),
]
PARTICIPANT_IDS = [
    bytes.fromhex("c07141ea606c145a73e3fdbd20ed429025cb88b83cf214a1a8a36d620aa827b8"),
    bytes.fromhex("c8324097723644e5a773c4c6e1040818a397d9907c94dd02031dff9df1ed0f5d"),
]
ADAPTOR_SECRET = 5
ADAPTOR_POINT = bytes.fromhex("022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4")

PURPOSE_CASES = [
    {
        "name": "V1-Refund",
        "session_id": bytes.fromhex("01" * 32),
        "purpose": 0x01,
        "template_hash": bytes.fromhex("cc" * 32),
        "kernel_message": bytes.fromhex("dd" * 32),
        "transcript_hash": bytes.fromhex("ee" * 32),
        "adaptor": False,
    },
    {
        "name": "V1-ClaimAdaptor",
        "session_id": bytes.fromhex("42" * 32),
        "purpose": 0x02,
        "template_hash": bytes.fromhex("ab" * 32),
        "kernel_message": bytes.fromhex("bc" * 32),
        "transcript_hash": bytes.fromhex("cd" * 32),
        "adaptor": True,
    },
    {
        "name": "V1-Funding",
        "session_id": bytes.fromhex("03" * 32),
        "purpose": 0x03,
        "template_hash": bytes.fromhex("ac" * 32),
        "kernel_message": bytes.fromhex("bd" * 32),
        "transcript_hash": bytes.fromhex("ce" * 32),
        "adaptor": False,
    },
]


class FullVectorError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def negate(point: ref.Point) -> ref.Point:
    if point is None:
        return None
    return point[0], (-point[1]) % ref.P


def subtract(left: ref.Point, right: ref.Point) -> ref.Point:
    return ref.point_add(left, negate(right))


def decode_point(encoded: bytes, name: str) -> ref.Point:
    return ref.decode_point(encoded, name)


def scalar_bytes(value: int) -> bytes:
    return (value % ref.N).to_bytes(32, "big")


def flip_first(value: bytes) -> bytes:
    return bytes([value[0] ^ 0x01]) + value[1:]


def participant_context(case: dict[str, Any], participant: int) -> dict[str, Any]:
    adaptor = bool(case["adaptor"])
    return {
        "context_version_u16_le": "0100",
        "chain_id_32": CHAIN_ID.hex(),
        "session_id_32": bytes(case["session_id"]).hex(),
        "purpose_u8": bytes([int(case["purpose"])]).hex(),
        "direction_u8": DIRECTIONS[participant].hex(),
        "signing_phase_u16_le": "0001",
        "template_hash_32": bytes(case["template_hash"]).hex(),
        "message_digest_32": bytes(case["kernel_message"]).hex(),
        "transcript_hash_32": bytes(case["transcript_hash"]).hex(),
        "retry_counter_u64_le": "0000000000000000",
        "participant_count_u16_le": "0200",
        "participant_public_keys_sec1": [value.hex() for value in ROSTER],
        "participant_index_u16_le": participant.to_bytes(2, "little").hex(),
        "signing_share_be32": scalar_bytes(SHARES[participant]).hex(),
        "signing_public_key_sec1": ROSTER[participant].hex(),
        "adaptor_presence_u8": "01" if adaptor else "00",
        "adaptor_point_sec1": ADAPTOR_POINT.hex() if adaptor else None,
        "adaptor_secret_be32": scalar_bytes(ADAPTOR_SECRET).hex() if adaptor else None,
        "aux_rand_32": AUX[participant].hex(),
    }


def verify_identity_assignments() -> list[dict[str, str]]:
    if PARTICIPANT_IDS[0] >= PARTICIPANT_IDS[1]:
        raise FullVectorError("participant IDs are not strictly ascending")
    records = []
    for index, (identity_key, expected_id) in enumerate(zip(IDENTITY_KEYS, PARTICIPANT_IDS)):
        decode_point(identity_key, f"identity_public_key[{index}]")
        tagged_input, participant_id = ref.tagged_hash(TAG_PARTICIPANT, CHAIN_ID + identity_key)
        if participant_id != expected_id:
            raise FullVectorError(f"participant ID {index} does not recompute")
        records.append(
            {
                "participant_index_u16_le": index.to_bytes(2, "little").hex(),
                "identity_public_key_sec1": identity_key.hex(),
                "participant_id_tag_input_bytes": tagged_input.hex(),
                "participant_id": participant_id.hex(),
                "signing_public_key_sec1": ROSTER[index].hex(),
            }
        )
    return records


def verify_signature_equation(
    signature: bytes, aggregate_excess: ref.Point, chain_id: bytes, kernel_message: bytes
) -> dict[str, Any]:
    if len(signature) != 65:
        return {"parsed": False, "equation": False, "reason": "signature_length"}
    try:
        r_point = decode_point(signature[:33], "signature.R")
    except ref.ReferenceError as error:
        return {"parsed": False, "equation": False, "reason": error.code}
    s = int.from_bytes(signature[33:], "big")
    if s == 0 or s >= ref.N:
        return {"parsed": False, "equation": False, "reason": "signature_scalar"}
    x_bytes = ref.encode_point(aggregate_excess)
    challenge_body = signature[:33] + x_bytes + chain_id + kernel_message
    challenge_input, challenge_digest = ref.tagged_hash(TAG_CHALLENGE, challenge_body)
    e = int.from_bytes(challenge_digest, "big")
    if e >= ref.N:
        return {
            "parsed": True,
            "equation": False,
            "reason": "challenge_noncanonical",
            "challenge_tag_input_bytes": challenge_input.hex(),
            "challenge_digest": challenge_digest.hex(),
        }
    left = ref.scalar_mul(s)
    right = ref.point_add(r_point, ref.scalar_mul(e, aggregate_excess))
    return {
        "parsed": True,
        "equation": left == right,
        "reason": None if left == right else "equation_mismatch",
        "challenge_tag_input_bytes": challenge_input.hex(),
        "challenge_digest": challenge_digest.hex(),
        "challenge_scalar_be32": scalar_bytes(e).hex(),
    }


def derive_case(case: dict[str, Any]) -> dict[str, Any]:
    purpose = int(case["purpose"])
    adaptor = bool(case["adaptor"])
    participant_outputs = []
    nonce_points: list[tuple[ref.Point, ref.Point]] = []
    commitments: list[bytes] = []

    for index in (0, 1):
        context_input = participant_context(case, index)
        kdf = ref.derive(context_input)
        r1_bytes = bytes.fromhex(kdf["R_i1_sec1"])
        r2_bytes = bytes.fromhex(kdf["R_i2_sec1"])
        r1 = decode_point(r1_bytes, f"{case['name']}.R_{index}1")
        r2 = decode_point(r2_bytes, f"{case['name']}.R_{index}2")
        nonce_points.append((r1, r2))

        commitment_body = (
            CHAIN_ID
            + bytes(case["session_id"])
            + PARTICIPANT_IDS[index]
            + bytes([purpose])
            + bytes(case["template_hash"])
            + r1_bytes
            + r2_bytes
            + (ADAPTOR_POINT if adaptor else b"")
        )
        expected_body_length = 228 if adaptor else 195
        if len(commitment_body) != expected_body_length:
            raise AssertionError("commitment body length")
        commitment_input, commitment = ref.tagged_hash(TAG_COMMITMENT, commitment_body)
        expected_tagged_length = 260 if adaptor else 227
        if len(commitment_input) != expected_tagged_length:
            raise AssertionError("commitment tagged-input length")
        commitments.append(commitment)
        commit_payload = bytes([purpose]) + index.to_bytes(2, "little") + commitment
        reveal_payload = bytes([purpose]) + index.to_bytes(2, "little") + r1_bytes + r2_bytes
        if len(commit_payload) != 35 or len(reveal_payload) != 69:
            raise AssertionError("commit/reveal payload length")
        participant_outputs.append(
            {
                "participant_index_u16_le": index.to_bytes(2, "little").hex(),
                "direction_u8": DIRECTIONS[index].hex(),
                "signing_share_be32": scalar_bytes(SHARES[index]).hex(),
                "signing_public_key_sec1": ROSTER[index].hex(),
                "aux_rand_32": AUX[index].hex(),
                "participant_id": PARTICIPANT_IDS[index].hex(),
                "kdf": kdf,
                "commitment_body": commitment_body.hex(),
                "commitment_tag_input_bytes": commitment_input.hex(),
                "nonce_commitment": commitment.hex(),
                "sig_nonce_commit_v1_35": commit_payload.hex(),
                "sig_nonce_reveal_v1_69": reveal_payload.hex(),
            }
        )

    binding_body = (
        CHAIN_ID
        + bytes(case["session_id"])
        + bytes([purpose])
        + bytes(case["template_hash"])
        + (2).to_bytes(4, "little")
        + b"".join(ROSTER)
        + (2).to_bytes(4, "little")
        + b"".join(
            ref.encode_point(point)
            for pair in nonce_points
            for point in pair
        )
        + (ADAPTOR_POINT if adaptor else b"")
    )
    expected_binding_body_length = 336 if adaptor else 303
    if len(binding_body) != expected_binding_body_length:
        raise AssertionError("binding body length")
    binding_input, binding_digest = ref.tagged_hash(TAG_BINDING, binding_body)
    expected_binding_input_length = 370 if adaptor else 337
    if len(binding_input) != expected_binding_input_length:
        raise AssertionError("binding tagged-input length")
    binding = int.from_bytes(binding_digest, "big")
    if binding == 0 or binding >= ref.N:
        raise FullVectorError(f"{case['name']} binding factor is outside [1,n-1]")

    effective_nonces = [
        ref.point_add(first, ref.scalar_mul(binding, second)) for first, second in nonce_points
    ]
    if any(point is None for point in effective_nonces):
        raise FullVectorError(f"{case['name']} effective nonce identity")
    aggregate_nonce = ref.point_add(effective_nonces[0], effective_nonces[1])
    if aggregate_nonce is None:
        raise FullVectorError(f"{case['name']} aggregate nonce identity")
    aggregate_excess = ref.point_add(
        decode_point(ROSTER[0], "X0"), decode_point(ROSTER[1], "X1")
    )
    if aggregate_excess is None:
        raise FullVectorError("aggregate excess identity")
    r_hat = ref.point_add(
        aggregate_nonce,
        decode_point(ADAPTOR_POINT, "T") if adaptor else None,
    )
    if r_hat is None:
        raise FullVectorError(f"{case['name']} R_hat identity")
    r_hat_bytes = ref.encode_point(r_hat)
    x_bytes = ref.encode_point(aggregate_excess)

    challenge_body = r_hat_bytes + x_bytes + CHAIN_ID + bytes(case["kernel_message"])
    if len(challenge_body) != 130:
        raise AssertionError("challenge body length")
    challenge_input, challenge_digest = ref.tagged_hash(TAG_CHALLENGE, challenge_body)
    if len(challenge_input) != 149:
        raise AssertionError("challenge tagged-input length")
    challenge = int.from_bytes(challenge_digest, "big")
    if challenge == 0 or challenge >= ref.N:
        raise FullVectorError(f"{case['name']} Scriptless challenge rejected")

    partials: list[int] = []
    partial_records = []
    for index in (0, 1):
        k1 = int(participant_outputs[index]["kdf"]["k1_be32"], 16)
        k2 = int(participant_outputs[index]["kdf"]["k2_be32"], 16)
        partial = (k1 + binding * k2 + challenge * SHARES[index]) % ref.N
        if partial == 0:
            raise FullVectorError(f"{case['name']} zero partial")
        left = ref.scalar_mul(partial)
        right = ref.point_add(effective_nonces[index], ref.scalar_mul(challenge, decode_point(ROSTER[index], f"X{index}")))
        if left != right:
            raise AssertionError("partial verification equation")
        partial_payload = (
            bytes([purpose])
            + index.to_bytes(2, "little")
            + bytes(case["template_hash"])
            + scalar_bytes(partial)
        )
        if len(partial_payload) != 67:
            raise AssertionError("partial payload length")
        partials.append(partial)
        partial_records.append(
            {
                "participant_index_u16_le": index.to_bytes(2, "little").hex(),
                "effective_nonce_sec1": ref.encode_point(effective_nonces[index]).hex(),
                "partial_scalar_be32": scalar_bytes(partial).hex(),
                "partial_signature_v1_67": partial_payload.hex(),
                "verification_left_sG_sec1": ref.encode_point(left).hex(),
                "verification_right_R_plus_eX_sec1": ref.encode_point(right).hex(),
                "verification_result": True,
            }
        )

    s_hat = sum(partials) % ref.N
    if s_hat == 0:
        raise FullVectorError(f"{case['name']} zero aggregate s_hat")
    aggregate_left = ref.scalar_mul(s_hat)
    aggregate_right = ref.point_add(aggregate_nonce, ref.scalar_mul(challenge, aggregate_excess))
    if aggregate_left != aggregate_right:
        raise AssertionError("aggregate pre-signature equation")
    core_65 = r_hat_bytes + scalar_bytes(s_hat)

    canonical_162: bytes | None = None
    extracted: int | None = None
    if adaptor:
        canonical_162 = (
            bytes(case["template_hash"])
            + ADAPTOR_POINT
            + r_hat_bytes
            + scalar_bytes(s_hat)
            + bytes(case["transcript_hash"])
        )
        if len(canonical_162) != 162:
            raise AssertionError("canonical pre-signature payload length")
        adapted_s = (s_hat + ADAPTOR_SECRET) % ref.N
        if adapted_s == 0:
            raise FullVectorError("zero adapted scalar")
        extracted = (adapted_s - s_hat) % ref.N
        if extracted != ADAPTOR_SECRET or ref.scalar_mul(extracted) != decode_point(ADAPTOR_POINT, "T"):
            raise AssertionError("adaptor extraction")
    else:
        adapted_s = s_hat
    final_signature = r_hat_bytes + scalar_bytes(adapted_s)
    independent_verify = verify_signature_equation(
        final_signature, aggregate_excess, CHAIN_ID, bytes(case["kernel_message"])
    )
    if not independent_verify["equation"]:
        raise AssertionError("independent DOM-compatible final verification")

    return {
        "name": case["name"],
        "inputs": {
            "chain_id_32": CHAIN_ID.hex(),
            "session_id_32": bytes(case["session_id"]).hex(),
            "purpose_u8": bytes([purpose]).hex(),
            "signing_phase_u16_le": "0001",
            "template_hash_32": bytes(case["template_hash"]).hex(),
            "kernel_message_digest_32": bytes(case["kernel_message"]).hex(),
            "transcript_hash_32": bytes(case["transcript_hash"]).hex(),
            "adaptor_secret_be32": scalar_bytes(ADAPTOR_SECRET).hex() if adaptor else None,
            "adaptor_point_sec1": ADAPTOR_POINT.hex() if adaptor else None,
        },
        "participants": participant_outputs,
        "binding": {
            "body": binding_body.hex(),
            "tag_input_bytes": binding_input.hex(),
            "digest": binding_digest.hex(),
            "scalar_be32": scalar_bytes(binding).hex(),
        },
        "effective_participant_nonces_sec1": [ref.encode_point(point).hex() for point in effective_nonces],
        "aggregate_nonce_R_sec1": ref.encode_point(aggregate_nonce).hex(),
        "aggregate_excess_X_sec1": x_bytes.hex(),
        "R_hat_sec1": r_hat_bytes.hex(),
        "challenge": {
            "body": challenge_body.hex(),
            "tag_input_bytes": challenge_input.hex(),
            "digest": challenge_digest.hex(),
            "scalar_be32": scalar_bytes(challenge).hex(),
        },
        "partials": partial_records,
        "aggregate_s_hat_be32": scalar_bytes(s_hat).hex(),
        "aggregate_pre_signature_left_s_hat_G_sec1": ref.encode_point(aggregate_left).hex(),
        "aggregate_pre_signature_right_R_plus_eX_sec1": ref.encode_point(aggregate_right).hex(),
        "aggregate_pre_signature_verification": True,
        "core_adaptor_pre_signature_65": core_65.hex() if adaptor else None,
        "aggregate_signature_core_65": core_65.hex() if not adaptor else None,
        "adaptor_pre_signature_v1_162": canonical_162.hex() if canonical_162 else None,
        "adapted_s_be32": scalar_bytes(adapted_s).hex() if adaptor else None,
        "final_dom_signature_65": final_signature.hex(),
        "extracted_t_be32": scalar_bytes(extracted).hex() if extracted is not None else None,
        "extracted_t_G_sec1": ref.encode_point(ref.scalar_mul(extracted)).hex() if extracted is not None else None,
        "extraction_matches_adaptor": extracted == ADAPTOR_SECRET if extracted is not None else None,
        "independent_dom_compatible_verification": independent_verify,
        "real_dom_verifier_execution": "DEFERRED UNTIL AFTER PRE-COMPARISON COMMIT",
    }


def signed_fixture_negative_results(repo_root: Path) -> list[dict[str, str]]:
    fixture_path = repo_root / "test-vectors/scriptless/two-nonce/kat_two_party_adaptor_inputs_v1.en.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    base = fixture["base_case"]
    records = []
    for mutation in fixture["rejected_mutations"]:
        expanded = supplemental.expand(base, mutation)
        try:
            supplemental.validate_case(expanded)
        except (ref.ReferenceError, supplemental.SupplementalInputError) as error:
            records.append(
                {
                    "name": mutation["name"],
                    "result": "reject",
                    "first_rejection": error.code,
                }
            )
        else:
            raise AssertionError(f"signed negative {mutation['name']} accepted")
    return records


def identity_negative_results() -> list[dict[str, Any]]:
    mutations = []

    invalid_prefix = bytes([0x04]) + IDENTITY_KEYS[0][1:]
    try:
        decode_point(invalid_prefix, "ID-N1")
    except ref.ReferenceError as error:
        mutations.append({"name": "ID-N1", "mutated_value": invalid_prefix.hex(), "result": "reject", "first_rejection": error.code})
    else:
        raise AssertionError("ID-N1 accepted")

    cases = [
        ("ID-N2", [IDENTITY_KEYS[1], IDENTITY_KEYS[1]], PARTICIPANT_IDS, "participant_id_recomputation"),
        ("ID-N3", IDENTITY_KEYS, [bytes.fromhex("c17141ea606c145a73e3fdbd20ed429025cb88b83cf214a1a8a36d620aa827b8"), PARTICIPANT_IDS[1]], "participant_id_recomputation"),
        ("ID-N4", IDENTITY_KEYS, [PARTICIPANT_IDS[1], PARTICIPANT_IDS[0]], "participant_id_mapping"),
        ("ID-N5", IDENTITY_KEYS, [PARTICIPANT_IDS[0], PARTICIPANT_IDS[0]], "duplicate_participant_id"),
    ]
    for name, keys, ids, expected in cases:
        if len(set(ids)) != len(ids):
            observed = "duplicate_participant_id"
        else:
            observed = None
            for key, claimed in zip(keys, ids):
                _, recomputed = ref.tagged_hash(TAG_PARTICIPANT, CHAIN_ID + key)
                if recomputed != claimed:
                    observed = expected
                    break
        if observed != expected:
            raise AssertionError(f"{name} observed {observed}, expected {expected}")
        mutations.append(
            {
                "name": name,
                "identity_keys_sec1": [value.hex() for value in keys],
                "participant_ids": [value.hex() for value in ids],
                "result": "reject",
                "first_rejection": observed,
            }
        )
    mutations.append(
        {
            "name": "ID-N6",
            "participant_id_to_signing_index": ["0100", "0000"],
            "result": "reject",
            "first_rejection": "frozen_one_to_one_mapping",
        }
    )
    return mutations


def commitment_negative_results(claim: dict[str, Any]) -> list[dict[str, str]]:
    participant = claim["participants"][0]
    fields = [
        ("chain_id", CHAIN_ID, "trusted_chain"),
        ("session_id", bytes.fromhex(claim["inputs"]["session_id_32"]), "bound_session"),
        ("participant_id", PARTICIPANT_IDS[0], "participant_id_mapping"),
        ("purpose", bytes.fromhex(claim["inputs"]["purpose_u8"]), "purpose_adaptor_compatibility"),
        ("template_hash", bytes.fromhex(claim["inputs"]["template_hash_32"]), "commitment_mismatch"),
        ("R_i1", bytes.fromhex(participant["kdf"]["R_i1_sec1"]), "commitment_mismatch"),
        ("R_i2", bytes.fromhex(participant["kdf"]["R_i2_sec1"]), "commitment_mismatch"),
        ("T", ADAPTOR_POINT, "commitment_mismatch"),
    ]
    return [
        {
            "name": f"COMMIT-{name}",
            "original": value.hex(),
            "mutated": flip_first(value).hex(),
            "retained_commitment": participant["nonce_commitment"],
            "result": "reject",
            "first_rejection": boundary,
        }
        for name, value, boundary in fields
    ]


def binding_negative_results(claim: dict[str, Any], refund: dict[str, Any], funding: dict[str, Any]) -> list[dict[str, Any]]:
    body = bytes.fromhex(claim["binding"]["body"])
    records = []
    for offset, label in ((97, "signing_key_count"), (167, "nonce_pair_count")):
        for count in (1, 3):
            mutated = body[:offset] + count.to_bytes(4, "little") + body[offset + 4 :]
            records.append({"name": f"BIND-{label}-{count}", "mutated_body": mutated.hex(), "result": "reject", "first_rejection": "count_mismatch"})
    swapped_keys = body[:101] + body[134:167] + body[101:134] + body[167:]
    records.append({"name": "BIND-swapped-signing-keys", "mutated_body": swapped_keys.hex(), "result": "reject", "first_rejection": "signing_key_order"})
    pair0, pair1 = body[171:237], body[237:303]
    swapped_pairs = body[:171] + pair1 + pair0 + body[303:]
    records.append({"name": "BIND-swapped-nonce-pairs", "mutated_body": swapped_pairs.hex(), "result": "reject", "first_rejection": "nonce_pair_association"})
    records.append({"name": "BIND-forbidden-participant-id", "mutated_body": (body + PARTICIPANT_IDS[0]).hex(), "result": "reject", "first_rejection": "trailing_bytes"})
    records.append({"name": "BIND-claim-missing-T", "mutated_body": body[:-33].hex(), "result": "reject", "first_rejection": "claim_missing_adaptor"})
    for non_adaptor in (refund, funding):
        non_body = bytes.fromhex(non_adaptor["binding"]["body"])
        records.append({"name": f"BIND-{non_adaptor['name']}-unexpected-T", "mutated_body": (non_body + ADAPTOR_POINT).hex(), "result": "reject", "first_rejection": "unexpected_adaptor"})
    return records


def challenge_and_equation_negative_results(claim: dict[str, Any]) -> list[dict[str, Any]]:
    signature = bytes.fromhex(claim["final_dom_signature_65"])
    x = decode_point(bytes.fromhex(claim["aggregate_excess_X_sec1"]), "X")
    chain = bytes.fromhex(claim["inputs"]["chain_id_32"])
    message = bytes.fromhex(claim["inputs"]["kernel_message_digest_32"])
    records = []
    mutated_signature = flip_first(signature[:33]) + signature[33:]
    check = verify_signature_equation(mutated_signature, x, chain, message)
    records.append({"name": "CHALLENGE-mutated-R-hat", "mutated_signature_65": mutated_signature.hex(), "result": "reject", "verification": check})
    x_bytes = bytes.fromhex(claim["aggregate_excess_X_sec1"])
    mutated_x = decode_point(flip_first(x_bytes), "mutated X")
    check = verify_signature_equation(signature, mutated_x, chain, message)
    records.append({"name": "CHALLENGE-mutated-X", "mutated_X_sec1": flip_first(x_bytes).hex(), "result": "reject", "verification": check})
    check = verify_signature_equation(signature, x, flip_first(chain), message)
    records.append({"name": "CHALLENGE-mutated-chain", "mutated_chain_id_32": flip_first(chain).hex(), "result": "reject", "verification": check})
    check = verify_signature_equation(signature, x, chain, flip_first(message))
    records.append({"name": "CHALLENGE-mutated-kernel-message", "mutated_kernel_message_digest_32": flip_first(message).hex(), "result": "reject", "verification": check})

    p0 = claim["partials"][0]
    partial = int(p0["partial_scalar_be32"], 16)
    effective_other = decode_point(bytes.fromhex(claim["partials"][1]["effective_nonce_sec1"]), "R1")
    other_x = decode_point(ROSTER[1], "X1")
    e = int(claim["challenge"]["scalar_be32"], 16)
    wrong_right = ref.point_add(effective_other, ref.scalar_mul(e, other_x))
    records.append({"name": "PARTIAL-participant-0-against-participant-1", "result": "reject", "equation_result": ref.scalar_mul(partial) == wrong_right})

    s_hat = int(claim["aggregate_s_hat_be32"], 16)
    wrong_s = (s_hat - ADAPTOR_SECRET) % ref.N
    wrong_signature = bytes.fromhex(claim["R_hat_sec1"]) + scalar_bytes(wrong_s)
    wrong_check = verify_signature_equation(wrong_signature, x, chain, message)
    records.append({"name": "ADAPT-subtraction-instead-of-addition", "wrong_signature_65": wrong_signature.hex(), "result": "reject", "verification": wrong_check, "wrong_extracted_t_be32": scalar_bytes((wrong_s - s_hat) % ref.N).hex()})
    for record in records:
        equation = record.get("equation_result")
        verification = record.get("verification")
        if equation is True or (isinstance(verification, dict) and verification.get("equation") is True):
            raise AssertionError(f"negative case {record['name']} verified")
    return records


def generate(repo_root: Path, generator_path: Path) -> dict[str, Any]:
    nar_path = repo_root / "docs/scriptless/source-guides/normative/amendments/NAR-002-phase-1-omnibus-normative-closure.en.md"
    nar_sig_path = Path(str(nar_path) + ".minisig")
    supplemental_path = repo_root / "test-vectors/scriptless/two-nonce/kat_two_party_adaptor_inputs_v1.en.json"
    supplemental_sig_path = Path(str(supplemental_path) + ".minisig")
    expected_hashes = [
        (nar_path, NAR_002_SHA256),
        (nar_sig_path, NAR_002_SIGNATURE_SHA256),
        (supplemental_path, SUPPLEMENTAL_INPUT_SHA256),
        (supplemental_sig_path, SUPPLEMENTAL_SIGNATURE_SHA256),
    ]
    for path, expected in expected_hashes:
        if sha256_file(path) != expected:
            raise FullVectorError(f"source hash mismatch: {path}")

    identity_records = verify_identity_assignments()
    cases = [derive_case(case) for case in PURPOSE_CASES]
    by_name = {case["name"]: case for case in cases}
    negatives = {
        "signed_supplemental_rejections": signed_fixture_negative_results(repo_root),
        "identity_rejections": identity_negative_results(),
        "commitment_rejections": commitment_negative_results(by_name["V1-ClaimAdaptor"]),
        "binding_rejections": binding_negative_results(by_name["V1-ClaimAdaptor"], by_name["V1-Refund"], by_name["V1-Funding"]),
        "challenge_partial_adaptation_rejections": challenge_and_equation_negative_results(by_name["V1-ClaimAdaptor"]),
    }
    return {
        "artifact": "DOM Scriptless Contracts independent complete two-party V1 outputs",
        "status": "PRE-COMPARISON INDEPENDENT EVIDENCE",
        "source_integrity": {
            "nar_002_sha256": NAR_002_SHA256,
            "nar_002_signature_sha256": NAR_002_SIGNATURE_SHA256,
            "supplemental_input_sha256": SUPPLEMENTAL_INPUT_SHA256,
            "supplemental_signature_sha256": SUPPLEMENTAL_SIGNATURE_SHA256,
            "minisign_key_id": "74197A95CA309CF0",
        },
        "implementation_boundary": {
            "language": platform.python_implementation(),
            "language_version": platform.python_version(),
            "dependencies": "Python standard library only; hashlib.blake2b and bounded pure-Python secp256k1 arithmetic",
            "generator_sha256": sha256_file(generator_path),
            "production_g1a_inspected": False,
            "production_dom_code_imported": False,
            "real_dom_verifier_deferred_until_after_commit": True,
        },
        "participant_identity_assignments": identity_records,
        "purpose_cases": cases,
        "negative_cases": negatives,
        "counts": {
            "purpose_cases": len(cases),
            "signed_supplemental_rejections": len(negatives["signed_supplemental_rejections"]),
            "identity_rejections": len(negatives["identity_rejections"]),
            "commitment_rejections": len(negatives["commitment_rejections"]),
            "binding_rejections": len(negatives["binding_rejections"]),
            "challenge_partial_adaptation_rejections": len(negatives["challenge_partial_adaptation_rejections"]),
        },
    }


def main() -> int:
    script_path = Path(__file__).resolve()
    repo_root = script_path.parents[5]
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=script_path.parent / "full_adaptor_reference_outputs_v1.json")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    document = generate(repo_root, script_path)
    encoded = (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != encoded:
            print(f"full reference output mismatch: {args.output}", file=sys.stderr)
            return 1
        print(f"full reference output verified: {args.output}")
        return 0
    args.output.write_bytes(encoded)
    print(
        f"wrote {args.output} ({document['counts']['purpose_cases']} purposes, "
        f"{sum(value for key, value in document['counts'].items() if key != 'purpose_cases')} negatives)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
