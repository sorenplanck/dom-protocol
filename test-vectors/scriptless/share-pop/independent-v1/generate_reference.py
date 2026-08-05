#!/usr/bin/env python3
"""Independent, dependency-free DOM Share PoK reference generator.

This program intentionally does not import DOM Rust code or third-party curve
implementations.  It implements only the public secp256k1 group operations
needed to generate and verify the public, insecure test vectors in this
directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Optional


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
TAG = b"DOM:scriptless-share-pop:v1"
STATEMENT_LENGTH = 196
PROOF_LENGTH = 65
ROOT = Path(__file__).resolve().parent
INPUTS_PATH = ROOT / "inputs_v1.json"
OUTPUTS_PATH = ROOT / "expected_outputs_v1.json"
MANIFEST_PATH = ROOT / "MANIFEST.sha256"
MANIFEST_MEMBERS = (
    ".gitignore",
    "README.md",
    "expected_outputs_v1.json",
    "generate_reference.py",
    "inputs_v1.json",
)

Point = Optional[tuple[int, int]]


class ReferenceError(ValueError):
    """A deterministic parsing, validation, or arithmetic failure."""


def decode_hex(value: str, size: int, name: str) -> bytes:
    if len(value) != size * 2 or value.lower() != value:
        raise ReferenceError(f"{name} must be {size} lowercase hex bytes")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise ReferenceError(f"{name} is not valid hex") from exc
    if result.hex() != value:
        raise ReferenceError(f"{name} is not canonical lowercase hex")
    return result


def tagged_input(tag: bytes, data: bytes) -> bytes:
    if not tag.isascii() or len(tag) > 0xFFFF:
        raise ReferenceError("tag must be ASCII and fit in u16")
    return len(tag).to_bytes(2, "little") + tag + data


def h_tag(tag: bytes, data: bytes) -> bytes:
    return hashlib.blake2b(tagged_input(tag, data), digest_size=32).digest()


def inverse(value: int) -> int:
    if value % P == 0:
        raise ReferenceError("attempted inversion of zero")
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
        slope = (3 * x1 * x1) * inverse(2 * y1) % P
    else:
        slope = (y2 - y1) * inverse(x2 - x1) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return (x3, y3)


def jacobian_double(point: tuple[int, int, int]) -> tuple[int, int, int]:
    x, y, z = point
    if z == 0 or y == 0:
        return (0, 1, 0)
    yy = y * y % P
    s = 4 * x * yy % P
    m = 3 * x * x % P
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * yy * yy) % P
    z3 = 2 * y * z % P
    return (x3, y3, z3)


def jacobian_add_affine(
    left: tuple[int, int, int], right: tuple[int, int]
) -> tuple[int, int, int]:
    x1, y1, z1 = left
    x2, y2 = right
    if z1 == 0:
        return (x2, y2, 1)
    z1z1 = z1 * z1 % P
    u2 = x2 * z1z1 % P
    s2 = y2 * z1 * z1z1 % P
    h = (u2 - x1) % P
    r = (s2 - y1) % P
    if h == 0:
        if r == 0:
            return jacobian_double(left)
        return (0, 1, 0)
    hh = h * h % P
    hhh = h * hh % P
    v = x1 * hh % P
    x3 = (r * r - hhh - 2 * v) % P
    y3 = (r * (v - x3) - y1 * hhh) % P
    z3 = z1 * h % P
    return (x3, y3, z3)


def jacobian_to_affine(point: tuple[int, int, int]) -> Point:
    x, y, z = point
    if z == 0:
        return None
    z_inverse = inverse(z)
    z_inverse_squared = z_inverse * z_inverse % P
    return (
        x * z_inverse_squared % P,
        y * z_inverse_squared * z_inverse % P,
    )


def scalar_mul(scalar: int, point: Point = G) -> Point:
    if scalar < 0:
        raise ReferenceError("negative scalar")
    if point is None or scalar == 0:
        return None
    result = (0, 1, 0)
    for bit in bin(scalar)[2:]:
        result = jacobian_double(result)
        if bit == "1":
            result = jacobian_add_affine(result, point)
    return jacobian_to_affine(result)


def encode_point(point: Point) -> bytes:
    if point is None:
        raise ReferenceError("identity point has no compressed SEC1 encoding")
    x, y = point
    return bytes((2 | (y & 1),)) + x.to_bytes(32, "big")


def decode_point(encoded: bytes, boundary: str) -> tuple[int, int]:
    if len(encoded) != 33 or encoded[0] not in (2, 3):
        raise ReferenceError(boundary)
    x = int.from_bytes(encoded[1:], "big")
    if x >= P:
        raise ReferenceError(boundary)
    rhs = (pow(x, 3, P) + 7) % P
    y = pow(rhs, (P + 1) // 4, P)
    if pow(y, 2, P) != rhs:
        raise ReferenceError(boundary)
    if (y & 1) != (encoded[0] & 1):
        y = P - y
    point = (x, y)
    if encode_point(point) != encoded:
        raise ReferenceError(boundary)
    return point


def canonical_nonzero_scalar(encoded: bytes, boundary: str) -> int:
    if len(encoded) != 32:
        raise ReferenceError(boundary)
    scalar = int.from_bytes(encoded, "big")
    if scalar == 0 or scalar >= N:
        raise ReferenceError(boundary)
    return scalar


def encode_statement(case: dict[str, Any], share_point: bytes) -> bytes:
    chain_id = decode_hex(case["chain_id_32"], 32, "chain_id_32")
    session_id = decode_hex(case["session_id_32"], 32, "session_id_32")
    participant_id = decode_hex(case["participant_id_32"], 32, "participant_id_32")
    terms_hash = decode_hex(case["terms_hash_32"], 32, "terms_hash_32")
    capsule_hash = decode_hex(case["capsule_hash_32"], 32, "capsule_hash_32")
    role = case["role_u8"]
    participant_index = case["participant_index_u16"]
    if role not in (1, 2):
        raise ReferenceError("invalid_role")
    if not isinstance(participant_index, int) or not 0 <= participant_index <= 15:
        raise ReferenceError("invalid_participant_index")
    if chain_id == bytes(32):
        raise ReferenceError("invalid_chain_id")
    if session_id == bytes(32):
        raise ReferenceError("invalid_session_id")
    if participant_id == bytes(32):
        raise ReferenceError("invalid_participant_id")
    decode_point(share_point, "invalid_share_point_encoding")
    statement = (
        chain_id
        + session_id
        + participant_id
        + bytes((role,))
        + participant_index.to_bytes(2, "little")
        + share_point
        + terms_hash
        + capsule_hash
    )
    if len(statement) != STATEMENT_LENGTH:
        raise AssertionError("statement length invariant failed")
    return statement


def parse_statement(statement: bytes) -> dict[str, Any]:
    if len(statement) != STATEMENT_LENGTH:
        raise ReferenceError("invalid_statement_length")
    chain_id = statement[0:32]
    session_id = statement[32:64]
    participant_id = statement[64:96]
    role = statement[96]
    participant_index = int.from_bytes(statement[97:99], "little")
    share_encoded = statement[99:132]
    if chain_id == bytes(32):
        raise ReferenceError("invalid_chain_id")
    if session_id == bytes(32):
        raise ReferenceError("invalid_session_id")
    if participant_id == bytes(32):
        raise ReferenceError("invalid_participant_id")
    if role not in (1, 2):
        raise ReferenceError("invalid_role")
    if participant_index > 15:
        raise ReferenceError("invalid_participant_index")
    share_point = decode_point(share_encoded, "invalid_share_point_encoding")
    return {
        "chain_id": chain_id,
        "session_id": session_id,
        "participant_id": participant_id,
        "role": role,
        "participant_index": participant_index,
        "share_encoded": share_encoded,
        "share_point": share_point,
        "terms_hash": statement[132:164],
        "capsule_hash": statement[164:196],
    }


def challenge_material(context_digest: bytes, share_point: bytes, announcement: bytes) -> dict[str, bytes | int]:
    preimage = context_digest + share_point + announcement
    digest_0_data = preimage + b"\x00"
    digest_1_data = preimage + b"\x01"
    digest_0 = h_tag(TAG, digest_0_data)
    digest_1 = h_tag(TAG, digest_1_data)
    wide = digest_0 + digest_1
    reduced = int.from_bytes(wide, "big") % N
    if reduced == 0:
        raise ReferenceError("zero_reduced_challenge")
    return {
        "preimage": preimage,
        "digest_0_data": digest_0_data,
        "digest_0_tagged_input": tagged_input(TAG, digest_0_data),
        "digest_0": digest_0,
        "digest_1_data": digest_1_data,
        "digest_1_tagged_input": tagged_input(TAG, digest_1_data),
        "digest_1": digest_1,
        "wide": wide,
        "reduced": reduced,
    }


def verify(statement: bytes, proof: bytes) -> dict[str, Any]:
    try:
        parsed = parse_statement(statement)
        if len(proof) != PROOF_LENGTH:
            raise ReferenceError("invalid_proof_length")
        announcement_encoded = proof[:33]
        announcement = decode_point(announcement_encoded, "invalid_announcement_encoding")
        response = canonical_nonzero_scalar(proof[33:], "noncanonical_response_scalar")
        context_digest = h_tag(TAG, statement)
        challenge = challenge_material(
            context_digest, parsed["share_encoded"], announcement_encoded
        )["reduced"]
        lhs = scalar_mul(response)
        rhs = point_add(announcement, scalar_mul(challenge, parsed["share_point"]))
        if lhs != rhs:
            raise ReferenceError("invalid_proof_equation")
        return {"accepted": True, "first_rejection": None}
    except ReferenceError as exc:
        return {"accepted": False, "first_rejection": str(exc)}


def generate_case(case: dict[str, Any]) -> tuple[dict[str, Any], bytes, bytes]:
    share_bytes = decode_hex(case["public_insecure_share_scalar_be32"], 32, "share scalar")
    nonce_bytes = decode_hex(case["public_insecure_pop_nonce_scalar_be32"], 32, "nonce scalar")
    share_scalar = canonical_nonzero_scalar(share_bytes, "noncanonical_share_scalar")
    nonce_scalar = canonical_nonzero_scalar(nonce_bytes, "noncanonical_nonce_scalar")
    share_point = encode_point(scalar_mul(share_scalar))
    known_share = decode_hex(case["known_public_share_sec1_33"], 33, "known public share")
    if share_point != known_share:
        raise ReferenceError(f"{case['case_id']}: known public share does not match scalar")
    statement = encode_statement(case, share_point)
    context_digest = h_tag(TAG, statement)
    announcement = encode_point(scalar_mul(nonce_scalar))
    challenge = challenge_material(context_digest, share_point, announcement)
    response = (nonce_scalar + int(challenge["reduced"]) * share_scalar) % N
    if response == 0:
        raise ReferenceError("zero_response_scalar")
    response_bytes = response.to_bytes(32, "big")
    proof = announcement + response_bytes
    verification = verify(statement, proof)
    if not verification["accepted"]:
        raise AssertionError(f"generated proof failed: {verification}")
    output = {
        "case_id": case["case_id"],
        "statement_length": len(statement),
        "statement_bytes": statement.hex(),
        "statement_tagged_input_bytes": tagged_input(TAG, statement).hex(),
        "share_point_sec1_33": share_point.hex(),
        "context_digest_32": context_digest.hex(),
        "pop_nonce_point_sec1_33": announcement.hex(),
        "challenge_preimage_bytes": bytes(challenge["preimage"]).hex(),
        "challenge_digest_0_data_bytes": bytes(challenge["digest_0_data"]).hex(),
        "challenge_digest_0_tagged_input_bytes": bytes(
            challenge["digest_0_tagged_input"]
        ).hex(),
        "challenge_digest_0_32": bytes(challenge["digest_0"]).hex(),
        "challenge_digest_1_data_bytes": bytes(challenge["digest_1_data"]).hex(),
        "challenge_digest_1_tagged_input_bytes": bytes(
            challenge["digest_1_tagged_input"]
        ).hex(),
        "challenge_digest_1_32": bytes(challenge["digest_1"]).hex(),
        "challenge_wide_digest_64": bytes(challenge["wide"]).hex(),
        "challenge_reduced_be32": int(challenge["reduced"]).to_bytes(32, "big").hex(),
        "response_be32": response_bytes.hex(),
        "proof_length": len(proof),
        "proof_bytes": proof.hex(),
        "verification": verification,
    }
    return output, statement, proof


def xor_at(value: bytes, offset: int, mask: int = 1) -> bytes:
    changed = bytearray(value)
    changed[offset] ^= mask
    return bytes(changed)


def mutation_vectors(base_statement: bytes, base_proof: bytes, alternate_share: bytes) -> list[dict[str, Any]]:
    mutations: list[tuple[str, str, bytes, bytes]] = [
        ("M01-chain-id-bit", "XOR 0x01 into statement chain_id byte 0", xor_at(base_statement, 0), base_proof),
        ("M02-session-id-bit", "XOR 0x01 into statement session_id byte 0", xor_at(base_statement, 32), base_proof),
        ("M03-participant-id-bit", "XOR 0x01 into statement participant_id byte 0", xor_at(base_statement, 64), base_proof),
        ("M04-role-valid-change", "Change role from Initiator (0x01) to Responder (0x02)", base_statement[:96] + b"\x02" + base_statement[97:], base_proof),
        ("M05-participant-index-change", "Change participant_index LE16 from 0 to 1", base_statement[:97] + b"\x01\x00" + base_statement[99:], base_proof),
        ("M06-share-point-valid-change", "Replace the complete share point with the second valid fixture share", base_statement[:99] + alternate_share + base_statement[132:], base_proof),
        ("M07-terms-hash-bit", "XOR 0x01 into statement terms_hash byte 0", xor_at(base_statement, 132), base_proof),
        ("M08-capsule-hash-bit", "XOR 0x01 into statement capsule_hash byte 0", xor_at(base_statement, 164), base_proof),
        ("M09-announcement-valid-change", "Replace the proof announcement with compressed secp256k1 G", base_statement, encode_point(G) + base_proof[33:]),
        ("M10-response-bit", "XOR 0x01 into the final response byte", base_statement, xor_at(base_proof, 64)),
        ("M11-proof-truncated", "Remove the final proof byte", base_statement, base_proof[:-1]),
        ("M12-proof-trailing", "Append one zero byte to the proof", base_statement, base_proof + b"\x00"),
        ("M13-announcement-prefix", "Replace the announcement SEC1 prefix with 0x04", base_statement, b"\x04" + base_proof[1:]),
        ("M14-response-equal-order", "Replace response with the secp256k1 group order", base_statement, base_proof[:33] + N.to_bytes(32, "big")),
        ("M15-response-zero", "Replace response with the all-zero scalar", base_statement, base_proof[:33] + bytes(32)),
        ("M16-chain-id-zero", "Replace chain_id with 32 zero bytes", bytes(32) + base_statement[32:], base_proof),
        ("M17-session-id-zero", "Replace session_id with 32 zero bytes", base_statement[:32] + bytes(32) + base_statement[64:], base_proof),
        ("M18-participant-id-zero", "Replace participant_id with 32 zero bytes", base_statement[:64] + bytes(32) + base_statement[96:], base_proof),
        ("M19-role-zero", "Replace role with unassigned 0x00", base_statement[:96] + b"\x00" + base_statement[97:], base_proof),
        ("M20-share-prefix", "Replace the share SEC1 prefix with 0x04", base_statement[:99] + b"\x04" + base_statement[100:], base_proof),
    ]
    outputs = []
    for mutation_id, description, statement, proof in mutations:
        result = verify(statement, proof)
        if result["accepted"]:
            raise AssertionError(f"negative mutation unexpectedly verified: {mutation_id}")
        outputs.append(
            {
                "mutation_id": mutation_id,
                "description": description,
                "statement_bytes": statement.hex(),
                "proof_bytes": proof.hex(),
                "verification": result,
            }
        )
    return outputs


def generate(inputs: dict[str, Any]) -> dict[str, Any]:
    if inputs.get("challenge_expansion") != "suffix-counter-00-01":
        raise ReferenceError("unsupported challenge expansion")
    generated = [generate_case(case) for case in inputs["cases"]]
    outputs = [entry[0] for entry in generated]
    mutations = mutation_vectors(generated[0][1], generated[0][2], bytes.fromhex(outputs[1]["share_point_sec1_33"]))
    return {
        "fixture": "DOM G1a Share PoK independent expected outputs v1",
        "warning": inputs["warning"],
        "reference_language": "Python 3 standard library only",
        "domain_tag_ascii": TAG.decode("ascii"),
        "domain_tag_length_u16_le": len(TAG).to_bytes(2, "little").hex(),
        "statement_layout": "chain_id_32 || session_id_32 || participant_id_32 || role_u8 || participant_index_u16_le || share_point_R_sec1_33 || terms_hash_32 || capsule_hash_32",
        "challenge_expansion": "d0 = H_tag(tag, challenge_preimage || 0x00); d1 = H_tag(tag, challenge_preimage || 0x01); wide = d0 || d1; c = BE512(wide) mod n; reject c=0",
        "proof_layout": "announcement_A_sec1_33 || response_z_be32",
        "group": {
            "field_prime_p_be32": P.to_bytes(32, "big").hex(),
            "group_order_n_be32": N.to_bytes(32, "big").hex(),
            "generator_sec1_33": encode_point(G).hex(),
        },
        "valid_cases": outputs,
        "negative_mutations": mutations,
    }


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def self_test() -> None:
    if scalar_mul(1) != G:
        raise AssertionError("secp256k1 generator multiplication failed")
    if scalar_mul(N) is not None:
        raise AssertionError("secp256k1 group-order identity check failed")
    if scalar_mul(N - 1) != (GX, (-GY) % P):
        raise AssertionError("secp256k1 negative-generator check failed")
    kernel_empty = "768031158853b4e3592808850df95afbe12abc27cd702b0563b8c7af2a789b51"
    if h_tag(b"DOM:kernel-sig:v1", b"").hex() != kernel_empty:
        raise AssertionError("DOM tagged BLAKE2b-256 framing check failed")


def manifest_text() -> str:
    rows = []
    for name in MANIFEST_MEMBERS:
        digest = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        rows.append(f"{digest}  {name}")
    return "\n".join(rows) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="write expected outputs and manifest")
    mode.add_argument("--check", action="store_true", help="verify committed outputs and manifest")
    args = parser.parse_args()

    self_test()
    inputs = json.loads(INPUTS_PATH.read_text(encoding="utf-8"))
    expected = canonical_json(generate(inputs))
    if args.write:
        OUTPUTS_PATH.write_text(expected, encoding="utf-8")
        MANIFEST_PATH.write_text(manifest_text(), encoding="utf-8")
        print(f"wrote {OUTPUTS_PATH.name} and {MANIFEST_PATH.name}")
        return 0
    if args.check:
        if not OUTPUTS_PATH.exists() or OUTPUTS_PATH.read_text(encoding="utf-8") != expected:
            raise SystemExit("expected_outputs_v1.json differs from a clean regeneration")
        committed_manifest = MANIFEST_PATH.read_text(encoding="utf-8")
        current_manifest = manifest_text()
        if committed_manifest != current_manifest:
            raise SystemExit("MANIFEST.sha256 differs from current member hashes")
        for line in committed_manifest.splitlines():
            digest, name = line.split("  ", 1)
            if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
                raise SystemExit(f"manifest verification failed for {name}")
        print("share-pop independent-v1 outputs and manifest verified")
        return 0
    print(expected, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
