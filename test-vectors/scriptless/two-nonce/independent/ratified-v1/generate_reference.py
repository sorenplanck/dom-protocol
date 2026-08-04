#!/usr/bin/env python3
"""Independent DOM Scriptless KDF V1 reference generator.

This evidence-only implementation intentionally uses only the Python standard
library and a small, bounded secp256k1 implementation. It does not import DOM
Rust crates or production Scriptless code.
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


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
Point = tuple[int, int] | None

TAG_AUX = "DOM:scriptless-secret-nonce-aux:v1"
TAG_SEED = "DOM:scriptless-secret-nonce-seed:v1"
TAG_WIDE = "DOM:scriptless-secret-nonce-wide:v1"
TRUSTED_CHAIN_ID = bytes.fromhex("aa" * 32)

PURPOSES = {0x01: "Refund", 0x02: "ClaimAdaptor", 0x03: "Funding", 0x04: "Sponsor"}
DIRECTIONS = {0x01: "Initiator", 0x02: "Responder"}
SIGNING_PHASES = {
    0x0100: "SigNonceCommit",
    0x0101: "SigNonceReveal",
    0x0102: "SigBinding",
    0x0103: "SigPartial",
    0x0104: "SigAdapt",
    0x0105: "SigExtract",
}


class ReferenceError(ValueError):
    """A deterministic fail-closed fixture rejection."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def reject(code: str, detail: str) -> None:
    raise ReferenceError(code, detail)


def decode_hex(value: Any, name: str, size: int | None = None) -> bytes:
    if not isinstance(value, str) or len(value) % 2 != 0:
        reject("invalid_hex", f"{name} must be an even-length hexadecimal string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        reject("invalid_hex", f"{name} is not hexadecimal")
    if decoded.hex() != value:
        reject("noncanonical_hex", f"{name} must use lowercase canonical hexadecimal")
    if size is not None and len(decoded) != size:
        reject("invalid_length", f"{name} must be exactly {size} bytes")
    return decoded


def inverse(value: int) -> int:
    if value % P == 0:
        raise ZeroDivisionError("inverse of zero")
    return pow(value, P - 2, P)


def point_add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if left == right:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1) * inverse(2 * y1) % P
    else:
        slope = (y2 - y1) * inverse(x2 - x1) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def scalar_mul(scalar: int, point: Point = G) -> Point:
    scalar %= N
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def encode_point(point: Point) -> bytes:
    if point is None:
        reject("identity_point", "the point at infinity has no canonical compressed SEC1 encoding")
    x, y = point
    return bytes([0x02 | (y & 1)]) + x.to_bytes(32, "big")


def decode_point(encoded: bytes, name: str) -> Point:
    if len(encoded) != 33 or encoded[0] not in (0x02, 0x03):
        reject("invalid_point", f"{name} is not a 33-byte compressed SEC1 point")
    x = int.from_bytes(encoded[1:], "big")
    if x >= P:
        reject("invalid_point", f"{name} x-coordinate is outside the base field")
    y_squared = (pow(x, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)
    if pow(y, 2, P) != y_squared:
        reject("invalid_point", f"{name} is not on secp256k1")
    if (y & 1) != (encoded[0] & 1):
        y = P - y
    point = (x, y)
    if encode_point(point) != encoded:
        reject("noncanonical_point", f"{name} does not re-encode byte-exactly")
    return point


def tagged_hash(tag: str, data: bytes) -> tuple[bytes, bytes]:
    tag_bytes = tag.encode("ascii")
    if len(tag_bytes) > 0xFFFF:
        raise ValueError("tag exceeds u16 framing")
    preimage = len(tag_bytes).to_bytes(2, "little") + tag_bytes + data
    return preimage, hashlib.blake2b(preimage, digest_size=32).digest()


def parse_u8(case: dict[str, Any], field: str) -> tuple[bytes, int]:
    encoded = decode_hex(case[field], field, 1)
    return encoded, encoded[0]


def parse_u16_le(case: dict[str, Any], field: str) -> tuple[bytes, int]:
    encoded = decode_hex(case[field], field, 2)
    return encoded, int.from_bytes(encoded, "little")


def validate_and_encode(case: dict[str, Any]) -> tuple[bytes, int, bytes, int]:
    version_bytes, version = parse_u16_le(case, "context_version_u16_le")
    if version != 1:
        reject("unknown_context_version", "SessionContextV1 version must be 0x0001")

    chain_id = decode_hex(case["chain_id_32"], "chain_id_32", 32)
    if chain_id == bytes(32) or chain_id != TRUSTED_CHAIN_ID:
        reject("untrusted_chain_id", "chain_id does not equal the fixture's trusted chain adapter value")
    session_id = decode_hex(case["session_id_32"], "session_id_32", 32)
    if session_id == bytes(32):
        reject("zero_session_id", "session_id must be nonzero")

    purpose_bytes, purpose = parse_u8(case, "purpose_u8")
    if purpose not in PURPOSES:
        reject("unknown_purpose", "unknown PurposeV1 discriminant")
    if purpose == 0x04:
        reject("sponsor_policy", "Sponsor is codec-valid but rejected by strict Phase 1 derivation")

    direction_bytes, direction = parse_u8(case, "direction_u8")
    if direction not in DIRECTIONS:
        reject("unknown_direction", "unknown DirectionV1 discriminant")

    phase_bytes, phase = parse_u16_le(case, "signing_phase_u16_le")
    if phase not in SIGNING_PHASES:
        reject("unknown_signing_phase", "value is outside the closed SigningPhaseV1 subregistry")

    template_hash = decode_hex(case["template_hash_32"], "template_hash_32", 32)
    message_digest = decode_hex(case["message_digest_32"], "message_digest_32", 32)
    transcript_hash = decode_hex(case["transcript_hash_32"], "transcript_hash_32", 32)
    retry_bytes = decode_hex(case["retry_counter_u64_le"], "retry_counter_u64_le", 8)
    retry_counter = int.from_bytes(retry_bytes, "little")

    count_bytes, participant_count = parse_u16_le(case, "participant_count_u16_le")
    roster_json = case.get("participant_public_keys_sec1")
    if not isinstance(roster_json, list):
        reject("invalid_roster", "participant roster must be an array")
    if not 2 <= participant_count <= 16 or len(roster_json) != participant_count:
        reject("invalid_participant_count", "participant count must match a roster of 2 through 16 entries")
    roster = [decode_hex(value, f"participant_public_keys_sec1[{index}]", 33) for index, value in enumerate(roster_json)]
    if len(set(roster)) != len(roster):
        reject("duplicate_participant", "participant roster contains a duplicate")
    for index, encoded in enumerate(roster):
        decode_point(encoded, f"participant_public_keys_sec1[{index}]")
    if any(left >= right for left, right in zip(roster, roster[1:])):
        reject("unsorted_participant_roster", "participant roster is not strictly ascending bytewise")

    index_bytes, participant_index = parse_u16_le(case, "participant_index_u16_le")
    if participant_index >= participant_count:
        reject("participant_index_out_of_range", "participant index is outside the roster")

    signing_share_bytes = decode_hex(case["signing_share_be32"], "signing_share_be32", 32)
    signing_share = int.from_bytes(signing_share_bytes, "big")
    if signing_share == 0 or signing_share >= N:
        reject("invalid_signing_scalar", "signing share must be in [1,n-1]")
    signing_public_key = decode_hex(case["signing_public_key_sec1"], "signing_public_key_sec1", 33)
    decode_point(signing_public_key, "signing_public_key_sec1")
    if encode_point(scalar_mul(signing_share)) != signing_public_key:
        reject("signing_key_mismatch", "signing_share*G does not equal signing_public_key")
    if roster.count(signing_public_key) != 1 or roster[participant_index] != signing_public_key:
        reject("signer_roster_mismatch", "signing key is not unique at participant_index")

    presence_bytes, adaptor_presence = parse_u8(case, "adaptor_presence_u8")
    if adaptor_presence not in (0, 1):
        reject("invalid_adaptor_presence", "adaptor presence must be 0x00 or 0x01")
    adaptor_json = case.get("adaptor_point_sec1")
    adaptor_point = b""
    if adaptor_presence == 1:
        if adaptor_json is None:
            reject("missing_adaptor_point", "present adaptor requires a point")
        adaptor_point = decode_hex(adaptor_json, "adaptor_point_sec1", 33)
        decoded_adaptor = decode_point(adaptor_point, "adaptor_point_sec1")
        secret_json = case.get("adaptor_secret_be32")
        if secret_json is not None:
            adaptor_secret_bytes = decode_hex(secret_json, "adaptor_secret_be32", 32)
            adaptor_secret = int.from_bytes(adaptor_secret_bytes, "big")
            if adaptor_secret == 0 or adaptor_secret >= N:
                reject("invalid_adaptor_scalar", "adaptor scalar must be in [1,n-1]")
            if scalar_mul(adaptor_secret) != decoded_adaptor:
                reject("adaptor_secret_mismatch", "adaptor_secret*G does not equal adaptor_point")
    elif adaptor_json is not None or case.get("adaptor_secret_be32") is not None:
        reject("noncanonical_adaptor_absence", "absent adaptor must append no point or secret")

    if purpose == 0x02 and adaptor_presence != 1:
        reject("claim_requires_adaptor", "ClaimAdaptor requires a canonical adaptor point")
    if purpose != 0x02 and adaptor_presence != 0:
        reject("unexpected_adaptor", "this purpose does not authorize an adaptor point")

    context = b"".join(
        [
            version_bytes,
            chain_id,
            session_id,
            purpose_bytes,
            direction_bytes,
            phase_bytes,
            template_hash,
            message_digest,
            transcript_hash,
            retry_bytes,
            count_bytes,
            *roster,
            index_bytes,
            presence_bytes,
            adaptor_point,
        ]
    )
    expected_size = 179 + 33 * participant_count + (33 if adaptor_presence else 0)
    if len(context) != expected_size:
        raise AssertionError("canonical context length invariant failed")
    return context, signing_share, signing_share_bytes, retry_counter


def derive(case: dict[str, Any]) -> dict[str, Any]:
    context, signing_share, signing_share_bytes, retry_counter = validate_and_encode(case)
    aux = decode_hex(case["aux_rand_32"], "aux_rand_32", 32)
    aux_preimage, mask = tagged_hash(TAG_AUX, aux)
    masked = bytes(left ^ right for left, right in zip(signing_share_bytes, mask))

    while True:
        seed_preimage, seed = tagged_hash(TAG_SEED, masked + context)
        nonce_records: list[dict[str, bytes | int]] = []
        any_zero = False
        for index in (1, 2):
            digest0_preimage, digest0 = tagged_hash(TAG_WIDE, seed + bytes([index, 0]))
            digest1_preimage, digest1 = tagged_hash(TAG_WIDE, seed + bytes([index, 1]))
            wide = digest0 + digest1
            scalar = int.from_bytes(wide, "big") % N
            any_zero |= scalar == 0
            nonce_records.append(
                {
                    "digest0_preimage": digest0_preimage,
                    "digest0": digest0,
                    "digest1_preimage": digest1_preimage,
                    "digest1": digest1,
                    "wide": wide,
                    "scalar": scalar,
                }
            )
        if not any_zero:
            break
        if retry_counter == 0xFFFFFFFFFFFFFFFF:
            reject("retry_counter_overflow", "zero-scalar retry counter overflow")
        retry_counter += 1
        retried = copy.deepcopy(case)
        retried["retry_counter_u64_le"] = retry_counter.to_bytes(8, "little").hex()
        context, retry_signing_share, retry_share_bytes, checked_counter = validate_and_encode(retried)
        if retry_signing_share != signing_share or retry_share_bytes != signing_share_bytes or checked_counter != retry_counter:
            raise AssertionError("retry changed an immutable input")

    k1 = int(nonce_records[0]["scalar"])
    k2 = int(nonce_records[1]["scalar"])
    if k1 == 0 or k2 == 0:
        raise AssertionError("zero scalar escaped retry")
    return {
        "canonical_context_bytes": context.hex(),
        "effective_retry_counter_u64_le": retry_counter.to_bytes(8, "little").hex(),
        "aux_tag_input_bytes": aux_preimage.hex(),
        "mask": mask.hex(),
        "masked_signing_share": masked.hex(),
        "seed_tag_input_bytes": seed_preimage.hex(),
        "seed": seed.hex(),
        "k1_wide_digest_0_tag_input_bytes": bytes(nonce_records[0]["digest0_preimage"]).hex(),
        "k1_wide_digest_0": bytes(nonce_records[0]["digest0"]).hex(),
        "k1_wide_digest_1_tag_input_bytes": bytes(nonce_records[0]["digest1_preimage"]).hex(),
        "k1_wide_digest_1": bytes(nonce_records[0]["digest1"]).hex(),
        "W_1": bytes(nonce_records[0]["wide"]).hex(),
        "k1_be32": k1.to_bytes(32, "big").hex(),
        "k2_wide_digest_0_tag_input_bytes": bytes(nonce_records[1]["digest0_preimage"]).hex(),
        "k2_wide_digest_0": bytes(nonce_records[1]["digest0"]).hex(),
        "k2_wide_digest_1_tag_input_bytes": bytes(nonce_records[1]["digest1_preimage"]).hex(),
        "k2_wide_digest_1": bytes(nonce_records[1]["digest1"]).hex(),
        "W_2": bytes(nonce_records[1]["wide"]).hex(),
        "k2_be32": k2.to_bytes(32, "big").hex(),
        "R_i1_sec1": encode_point(scalar_mul(k1)).hex(),
        "R_i2_sec1": encode_point(scalar_mul(k2)).hex(),
    }


EXPECTED_REJECTION_CODES = {
    "N1-purpose-zero": "unknown_purpose",
    "N2-purpose-sponsor-strict-phase1": "sponsor_policy",
    "N3-purpose-unknown": "unknown_purpose",
    "N4-direction-invalid": "unknown_direction",
    "N5-base-phase-outside-signing-subregistry": "unknown_signing_phase",
    "N6-session-zero": "zero_session_id",
    "N7-participant-duplicate": "duplicate_participant",
    "N8-participant-unsorted": "unsorted_participant_roster",
    "N9-participant-invalid-prefix": "invalid_point",
    "N10-participant-index-out-of-range": "participant_index_out_of_range",
    "N11-claim-adaptor-identity": "invalid_point",
    "N12-secret-public-key-mismatch": "signing_key_mismatch",
    "N13-claim-missing-adaptor": "claim_requires_adaptor",
    "N14-refund-unexpected-adaptor": "unexpected_adaptor",
    "N15-funding-unexpected-adaptor": "unexpected_adaptor",
    "N16-signing-share-zero": "invalid_signing_scalar",
    "N17-signing-share-equal-group-order": "invalid_signing_scalar",
    "N18-adaptor-presence-invalid": "invalid_adaptor_presence",
    "N19-context-version-unknown": "unknown_context_version",
    "N20-chain-id-zero": "untrusted_chain_id",
}


def expand_case(base_cases: dict[str, dict[str, Any]], mutation: dict[str, Any]) -> dict[str, Any]:
    allowed = {"name", "base_case", "replace", "expected"}
    if set(mutation) != allowed:
        raise ValueError(f"mutation {mutation.get('name')} has unknown or missing fields")
    base_name = mutation["base_case"]
    if base_name not in base_cases:
        raise ValueError(f"unknown base case {base_name}")
    replacements = mutation["replace"]
    if not isinstance(replacements, dict):
        raise ValueError("replace must be an object")
    result = copy.deepcopy(base_cases[base_name])
    for key, value in replacements.items():
        if key not in result:
            raise ValueError(f"unknown replacement field {key}")
        result[key] = copy.deepcopy(value)
    result["name"] = mutation["name"]
    result["expected"] = mutation["expected"]
    return result


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate(input_path: Path, generator_path: Path) -> dict[str, Any]:
    fixture = json.loads(input_path.read_text(encoding="utf-8"))
    if fixture["curve"]["order_n_be32"] != N.to_bytes(32, "big").hex():
        raise ValueError("fixture group order differs from secp256k1")
    base_cases = {case["name"]: case for case in fixture["base_cases"]}
    if len(base_cases) != len(fixture["base_cases"]):
        raise ValueError("duplicate base-case name")

    accepted: list[dict[str, Any]] = []
    base_outputs: dict[str, dict[str, Any]] = {}
    for case in fixture["base_cases"]:
        output = derive(case)
        base_outputs[case["name"]] = output
        accepted.append({"name": case["name"], "source": "base_case", "result": "accept", "outputs": output})
    for mutation in fixture["accepted_mutations"]:
        case = expand_case(base_cases, mutation)
        output = derive(case)
        base_output = base_outputs[mutation["base_case"]]
        changed = [key for key in output if output[key] != base_output.get(key)]
        accepted.append(
            {
                "name": mutation["name"],
                "source": "accepted_mutation",
                "base_case": mutation["base_case"],
                "replacements": mutation["replace"],
                "result": "accept",
                "changed_outputs_relative_to_base": changed,
                "outputs": output,
            }
        )

    rejected: list[dict[str, Any]] = []
    for mutation in fixture["rejected_mutations"]:
        case = expand_case(base_cases, mutation)
        try:
            derive(case)
        except ReferenceError as error:
            expected_code = EXPECTED_REJECTION_CODES.get(mutation["name"])
            if expected_code is None or error.code != expected_code:
                raise AssertionError(
                    f"{mutation['name']} rejected as {error.code}, expected {expected_code}"
                ) from error
            rejected.append(
                {
                    "name": mutation["name"],
                    "base_case": mutation["base_case"],
                    "replacements": mutation["replace"],
                    "result": "reject",
                    "rejection_code": error.code,
                    "detail": error.detail,
                }
            )
        else:
            raise AssertionError(f"negative case {mutation['name']} was accepted")

    return {
        "artifact": "DOM Scriptless Contracts independent KDF V1 reference outputs",
        "status": "PRE-COMPARISON INDEPENDENT EVIDENCE",
        "normative_source": "Ratified NAR-001 and signed input-only KAT V2",
        "implementation_boundary": {
            "language": platform.python_implementation(),
            "language_version": platform.python_version(),
            "dependencies": "Python standard library only; hashlib.blake2b and bounded pure-Python secp256k1 arithmetic",
            "generator_sha256": sha256_file(generator_path),
            "production_dom_code_imported": False,
            "production_g1a_inspected": False,
        },
        "source_integrity": {
            "input_path": "test-vectors/scriptless/two-nonce/kat_inputs_v2.en.json",
            "input_sha256": sha256_file(input_path),
            "nar_sha256": "eee087c808aeb4e6e745a5311d17ca5a63c5b5e5568218d20b1cbcdd7b6206dc",
            "minisign_key_id": "74197A95CA309CF0",
        },
        "hash_definition": {
            "digest": "native BLAKE2b-256",
            "framing": "u16_le(len(tag_ascii)) || tag_ascii || data",
            "key": None,
            "salt": None,
            "personalization": None,
        },
        "curve": {
            "name": "secp256k1",
            "order_n_be32": N.to_bytes(32, "big").hex(),
            "point_encoding": "33-byte canonical compressed SEC1",
        },
        "counts": {"accepted": len(accepted), "rejected": len(rejected)},
        "accepted_cases": accepted,
        "rejected_cases": rejected,
        "supplemental_full_adaptor_evidence": {
            "generated": False,
            "reason": "The signed input fixture supplies one local nonce derivation per case but no complete multi-party nonce inputs. Creating the missing participant inputs would be a supplemental construction, not an output derived solely from the signed fixture.",
        },
    }


def main() -> int:
    script_path = Path(__file__).resolve()
    repo_root = script_path.parents[5]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        type=Path,
        default=repo_root / "test-vectors/scriptless/two-nonce/kat_inputs_v2.en.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=script_path.parent / "reference_outputs_v1.json",
    )
    parser.add_argument("--check", action="store_true", help="verify that the existing output is byte-exact")
    args = parser.parse_args()
    document = generate(args.input.resolve(), script_path)
    encoded = (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != encoded:
            print(f"reference output mismatch: {args.output}", file=sys.stderr)
            return 1
        print(f"reference output verified: {args.output}")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    print(f"wrote {args.output} ({len(document['accepted_cases'])} accepted, {len(document['rejected_cases'])} rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
