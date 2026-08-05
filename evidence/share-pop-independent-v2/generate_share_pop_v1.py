#!/usr/bin/env python3
"""Independent deterministic Share PoP V1 evidence generator and verifier.

This file deliberately uses Python's BLAKE2b-256 implementation and the
OpenSSL secp256k1 primitives exposed by cryptography, rather than the Rust
implementation under later comparison.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import cryptography
from cryptography.hazmat.bindings.openssl.binding import Binding


GROUP_ORDER = int(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    16,
)
STATEMENT_TAG = "DOM:scriptless-share-pop:v1"
CHALLENGE_TAG = "DOM:scriptless-share-pop-challenge:v1"
STATEMENT_LENGTH = 202
PROOF_LENGTH = 65

CHAIN_ID = bytes.fromhex("11" * 32)
SESSION_ID = bytes.fromhex("22" * 32)
ROSTER = (bytes.fromhex("21" * 32), bytes.fromhex("42" * 32))
ROLE = 0x01
PARTICIPANT_INDEX = 0
SIGNING_SHARE = 7
EVIDENCE_NONCE = 9
TERMS_HASH = bytes.fromhex("33" * 32)
RECOVERY_BINDING_HASH = bytes.fromhex("44" * 32)


def hex_bytes(value: bytes) -> str:
    return value.hex()


def scalar_bytes(value: int) -> bytes:
    if not 0 <= value < GROUP_ORDER:
        raise ValueError("scalar is outside the canonical range")
    return value.to_bytes(32, "big")


def h_tag(tag: str, data: bytes) -> tuple[bytes, bytes]:
    tag_bytes = tag.encode("ascii")
    if len(tag_bytes) > 0xFFFF:
        raise ValueError("tag exceeds u16 length")
    preimage = len(tag_bytes).to_bytes(2, "little") + tag_bytes + data
    return hashlib.blake2b(preimage, digest_size=32).digest(), preimage


class Secp256k1:
    """Small ownership wrapper over the OpenSSL EC primitives."""

    def __init__(self) -> None:
        binding = Binding()
        self.ffi = binding.ffi
        self.lib = binding.lib
        nid = self.lib.OBJ_txt2nid(b"secp256k1")
        if nid == 0:
            raise RuntimeError("OpenSSL does not provide secp256k1")
        group = self.lib.EC_GROUP_new_by_curve_name(nid)
        if group == self.ffi.NULL:
            raise RuntimeError("EC_GROUP_new_by_curve_name failed")
        self.group = self.ffi.gc(group, self.lib.EC_GROUP_free)
        ctx = self.lib.BN_CTX_new()
        if ctx == self.ffi.NULL:
            raise RuntimeError("BN_CTX_new failed")
        self.ctx = self.ffi.gc(ctx, self.lib.BN_CTX_free)

    def _bn(self, value: int):
        if not 0 <= value < GROUP_ORDER:
            raise ValueError("scalar is outside the canonical range")
        raw = value.to_bytes(32, "big")
        bn = self.lib.BN_bin2bn(raw, len(raw), self.ffi.NULL)
        if bn == self.ffi.NULL:
            raise RuntimeError("BN_bin2bn failed")
        return self.ffi.gc(bn, self.lib.BN_free)

    def _new_point(self):
        point = self.lib.EC_POINT_new(self.group)
        if point == self.ffi.NULL:
            raise RuntimeError("EC_POINT_new failed")
        return self.ffi.gc(point, self.lib.EC_POINT_free)

    def _encode_point(self, point) -> bytes:
        size = self.lib.EC_POINT_point2oct(
            self.group,
            point,
            self.lib.POINT_CONVERSION_COMPRESSED,
            self.ffi.NULL,
            0,
            self.ctx,
        )
        if size != 33:
            raise RuntimeError("unexpected compressed point length")
        output = self.ffi.new("unsigned char[]", size)
        written = self.lib.EC_POINT_point2oct(
            self.group,
            point,
            self.lib.POINT_CONVERSION_COMPRESSED,
            output,
            size,
            self.ctx,
        )
        if written != size:
            raise RuntimeError("EC_POINT_point2oct failed")
        return bytes(self.ffi.buffer(output, size))

    def parse_point(self, encoded: bytes):
        if len(encoded) != 33 or encoded[0] not in (0x02, 0x03):
            raise ValueError("point is not a 33-byte compressed SEC1 encoding")
        point = self._new_point()
        source = self.ffi.new("unsigned char[]", encoded)
        if self.lib.EC_POINT_oct2point(
            self.group, point, source, len(encoded), self.ctx
        ) != 1:
            raise ValueError("point is not on secp256k1")
        if self.lib.EC_POINT_is_at_infinity(self.group, point) == 1:
            raise ValueError("point is the identity")
        if self._encode_point(point) != encoded:
            raise ValueError("point encoding is noncanonical")
        return point

    def scalar_point(self, scalar: int) -> bytes:
        if not 1 <= scalar < GROUP_ORDER:
            raise ValueError("point scalar must be nonzero and canonical")
        output = self._new_point()
        scalar_bn = self._bn(scalar)
        if self.lib.EC_POINT_mul(
            self.group,
            output,
            scalar_bn,
            self.ffi.NULL,
            self.ffi.NULL,
            self.ctx,
        ) != 1:
            raise RuntimeError("EC_POINT_mul(generator) failed")
        return self._encode_point(output)

    def linear_combination(
        self, generator_scalar: int, encoded_point: bytes, point_scalar: int
    ) -> bytes:
        """Return generator_scalar*G + point_scalar*encoded_point."""
        point = self.parse_point(encoded_point)
        output = self._new_point()
        generator_bn = self._bn(generator_scalar)
        point_bn = self._bn(point_scalar)
        if self.lib.EC_POINT_mul(
            self.group,
            output,
            generator_bn,
            point,
            point_bn,
            self.ctx,
        ) != 1:
            raise RuntimeError("EC_POINT_mul(linear combination) failed")
        if self.lib.EC_POINT_is_at_infinity(self.group, output) == 1:
            raise ValueError("linear combination is the identity")
        return self._encode_point(output)

    def points_equal(self, left: bytes, right: bytes) -> bool:
        left_point = self.parse_point(left)
        right_point = self.parse_point(right)
        return self.lib.EC_POINT_cmp(
            self.group, left_point, right_point, self.ctx
        ) == 0

    def openssl_version(self) -> str:
        return self.ffi.string(self.lib.OpenSSL_version(0)).decode("ascii")


@dataclass(frozen=True)
class ExpectedContext:
    chain_id: bytes
    session_id: bytes
    roster: tuple[bytes, ...]
    role: int
    participant_index: int
    terms_hash: bytes
    recovery_binding_hash: bytes


EXPECTED = ExpectedContext(
    chain_id=CHAIN_ID,
    session_id=SESSION_ID,
    roster=ROSTER,
    role=ROLE,
    participant_index=PARTICIPANT_INDEX,
    terms_hash=TERMS_HASH,
    recovery_binding_hash=RECOVERY_BINDING_HASH,
)


def validate_roster(roster: tuple[bytes, ...]) -> None:
    if not roster:
        raise ValueError("roster is empty")
    if any(len(participant_id) != 32 or not any(participant_id) for participant_id in roster):
        raise ValueError("roster participant identifier is malformed or zero")
    if tuple(sorted(roster)) != roster:
        raise ValueError("roster is not ascending")
    if len(set(roster)) != len(roster):
        raise ValueError("roster contains a duplicate participant")


def encode_statement(share_point: bytes) -> bytes:
    validate_roster(ROSTER)
    if PARTICIPANT_INDEX >= len(ROSTER):
        raise ValueError("participant index is outside roster")
    statement = b"".join(
        (
            b"DSPO",
            (1).to_bytes(2, "little"),
            CHAIN_ID,
            SESSION_ID,
            ROSTER[PARTICIPANT_INDEX],
            bytes((ROLE,)),
            PARTICIPANT_INDEX.to_bytes(2, "little"),
            share_point,
            TERMS_HASH,
            RECOVERY_BINDING_HASH,
        )
    )
    if len(statement) != STATEMENT_LENGTH:
        raise AssertionError("internal statement length error")
    return statement


def parse_statement(
    statement: bytes, secp: Secp256k1, expected: ExpectedContext
) -> dict[str, Any]:
    if len(statement) != STATEMENT_LENGTH:
        raise ValueError("statement length is not exactly 202")
    if statement[0:4] != b"DSPO":
        raise ValueError("statement magic mismatch")
    if statement[4:6] != b"\x01\x00":
        raise ValueError("statement version mismatch")

    chain_id = statement[6:38]
    session_id = statement[38:70]
    participant_id = statement[70:102]
    role = statement[102]
    participant_index = int.from_bytes(statement[103:105], "little")
    share_point = statement[105:138]
    terms_hash = statement[138:170]
    recovery_binding_hash = statement[170:202]

    for label, value in (
        ("chain_id", chain_id),
        ("session_id", session_id),
        ("participant_id", participant_id),
        ("terms_hash", terms_hash),
        ("recovery_binding_hash", recovery_binding_hash),
    ):
        if not any(value):
            raise ValueError(f"{label} is zero")
    if role not in (0x01, 0x02):
        raise ValueError("role is not registered")

    validate_roster(expected.roster)
    if participant_index >= len(expected.roster):
        raise ValueError("participant index is outside roster")
    if participant_id != expected.roster[participant_index]:
        raise ValueError("participant identifier does not match roster index")
    secp.parse_point(share_point)

    if chain_id != expected.chain_id:
        raise ValueError("chain_id does not match expected context")
    if session_id != expected.session_id:
        raise ValueError("session_id does not match expected context")
    if role != expected.role:
        raise ValueError("role does not match expected context")
    if participant_index != expected.participant_index:
        raise ValueError("participant index does not match expected context")
    if terms_hash != expected.terms_hash:
        raise ValueError("terms_hash does not match expected context")
    if recovery_binding_hash != expected.recovery_binding_hash:
        raise ValueError("recovery_binding_hash does not match expected context")

    return {
        "chain_id": chain_id,
        "session_id": session_id,
        "participant_id": participant_id,
        "role": role,
        "participant_index": participant_index,
        "share_point": share_point,
        "terms_hash": terms_hash,
        "recovery_binding_hash": recovery_binding_hash,
    }


def derive_challenge(
    context_digest: bytes, share_point: bytes, nonce_commitment: bytes
) -> dict[str, Any]:
    counter = 0
    while True:
        counter_le = counter.to_bytes(4, "little")
        challenge_input = (
            context_digest + share_point + nonce_commitment + counter_le
        )
        d0, d0_preimage = h_tag(CHALLENGE_TAG, b"\x00" + challenge_input)
        d1, d1_preimage = h_tag(CHALLENGE_TAG, b"\x01" + challenge_input)
        wide = d0 + d1
        reduced = int.from_bytes(wide, "big") % GROUP_ORDER
        if reduced != 0:
            return {
                "counter": counter,
                "counter_le": counter_le,
                "input": challenge_input,
                "d0_data": b"\x00" + challenge_input,
                "d0_preimage": d0_preimage,
                "d0": d0,
                "d1_data": b"\x01" + challenge_input,
                "d1_preimage": d1_preimage,
                "d1": d1,
                "wide": wide,
                "scalar": reduced,
            }
        if counter == 0xFFFFFFFF:
            raise OverflowError("challenge counter overflow")
        counter += 1


def verify(
    statement: bytes,
    proof: bytes,
    secp: Secp256k1,
    expected: ExpectedContext = EXPECTED,
) -> tuple[bool, str]:
    try:
        fields = parse_statement(statement, secp, expected)
        if len(proof) != PROOF_LENGTH:
            raise ValueError("proof length is not exactly 65")
        nonce_commitment = proof[0:33]
        secp.parse_point(nonce_commitment)
        response = int.from_bytes(proof[33:65], "big")
        if response >= GROUP_ORDER:
            raise ValueError("response scalar is noncanonical")

        context_digest, _ = h_tag(STATEMENT_TAG, statement)
        challenge = derive_challenge(
            context_digest, fields["share_point"], nonce_commitment
        )["scalar"]

        # zG == A + cR is equivalent to zG + (q-c)R == A.  This form lets
        # the verifier use OpenSSL's combined multiplication without knowing a.
        rearranged_left = secp.linear_combination(
            response, fields["share_point"], (-challenge) % GROUP_ORDER
        )
        if not secp.points_equal(rearranged_left, nonce_commitment):
            raise ValueError("Schnorr verification equation mismatch")
        return True, "accepted"
    except (ValueError, OverflowError, RuntimeError) as exc:
        return False, str(exc)


def mutate_byte(value: bytes, offset: int, mask: int) -> bytes:
    changed = bytearray(value)
    changed[offset] ^= mask
    return bytes(changed)


def targeted_negative_cases(
    statement: bytes, proof: bytes, secp: Secp256k1
) -> list[dict[str, Any]]:
    cases: list[tuple[str, str, bytes, bytes, ExpectedContext]] = []

    def add(name: str, description: str, st: bytes, pr: bytes, ctx: ExpectedContext = EXPECTED) -> None:
        cases.append((name, description, st, pr, ctx))

    add("statement_truncated", "Remove the last statement byte.", statement[:-1], proof)
    add("statement_trailing", "Append one trailing statement byte.", statement + b"\x00", proof)
    add("bad_magic", "Flip one bit in DSPO magic.", mutate_byte(statement, 0, 0x01), proof)
    add("bad_version", "Flip one bit in the little-endian version.", mutate_byte(statement, 4, 0x02), proof)
    add("zero_chain_id", "Replace chain_id with zero.", statement[:6] + bytes(32) + statement[38:], proof)
    add("wrong_chain_id", "Flip one bit in chain_id.", mutate_byte(statement, 6, 0x01), proof)
    add("zero_session_id", "Replace session_id with zero.", statement[:38] + bytes(32) + statement[70:], proof)
    add("wrong_session_id", "Flip one bit in session_id.", mutate_byte(statement, 38, 0x01), proof)
    add("zero_participant_id", "Replace participant_id with zero.", statement[:70] + bytes(32) + statement[102:], proof)
    add("wrong_participant_id", "Use the other roster participant at index zero.", statement[:70] + ROSTER[1] + statement[102:], proof)
    invalid_role = statement[:102] + b"\x00" + statement[103:]
    add("invalid_role", "Set role to unregistered zero.", invalid_role, proof)
    responder_role = statement[:102] + b"\x02" + statement[103:]
    add("role_mismatch", "Change Initiator to Responder.", responder_role, proof)
    index_one = statement[:103] + b"\x01\x00" + statement[105:]
    add("index_roster_mismatch", "Change index zero to one without changing participant_id.", index_one, proof)
    index_two = statement[:103] + b"\x02\x00" + statement[105:]
    add("index_out_of_range", "Set index equal to roster length.", index_two, proof)
    add("invalid_share_point", "Replace share point with a non-SEC1 all-zero surrogate.", statement[:105] + bytes(33) + statement[138:], proof)
    alternate_share = secp.scalar_point(8)
    add("wrong_valid_share_point", "Replace 7G with the valid point 8G.", statement[:105] + alternate_share + statement[138:], proof)
    add("zero_terms_hash", "Replace terms_hash with zero.", statement[:138] + bytes(32) + statement[170:], proof)
    add("wrong_terms_hash", "Flip one bit in terms_hash.", mutate_byte(statement, 138, 0x01), proof)
    add("zero_recovery_binding", "Replace recovery binding hash with zero.", statement[:170] + bytes(32), proof)
    add("wrong_recovery_binding", "Flip one bit in recovery binding hash.", mutate_byte(statement, 170, 0x01), proof)
    add("proof_truncated", "Remove the last proof byte.", statement, proof[:-1])
    add("proof_trailing", "Append one trailing proof byte.", statement, proof + b"\x00")
    add("invalid_nonce_commitment", "Replace A with a non-SEC1 all-zero surrogate.", statement, bytes(33) + proof[33:])
    alternate_nonce = secp.scalar_point(10)
    add("wrong_valid_nonce_commitment", "Replace 9G with the valid point 10G.", statement, alternate_nonce + proof[33:])
    add("zero_response", "Set the structurally permitted response to zero; the equation still fails.", statement, proof[:33] + bytes(32))
    add("noncanonical_response_q", "Set response bytes equal to group order q.", statement, proof[:33] + GROUP_ORDER.to_bytes(32, "big"))
    response = int.from_bytes(proof[33:], "big")
    altered_response = (response + 1) % GROUP_ORDER
    add("wrong_canonical_response", "Increment response modulo q.", statement, proof[:33] + scalar_bytes(altered_response))

    duplicate_context = ExpectedContext(
        CHAIN_ID,
        SESSION_ID,
        (ROSTER[0], ROSTER[0]),
        ROLE,
        PARTICIPANT_INDEX,
        TERMS_HASH,
        RECOVERY_BINDING_HASH,
    )
    add("duplicate_roster", "Supply a duplicate participant roster.", statement, proof, duplicate_context)
    descending_context = ExpectedContext(
        CHAIN_ID,
        SESSION_ID,
        (ROSTER[1], ROSTER[0]),
        ROLE,
        PARTICIPANT_INDEX,
        TERMS_HASH,
        RECOVERY_BINDING_HASH,
    )
    add("descending_roster", "Supply a nonascending participant roster.", statement, proof, descending_context)
    responder_context = ExpectedContext(
        CHAIN_ID,
        SESSION_ID,
        ROSTER,
        0x02,
        PARTICIPANT_INDEX,
        TERMS_HASH,
        RECOVERY_BINDING_HASH,
    )
    add("expected_role_mismatch", "Verify the Initiator statement in a Responder context.", statement, proof, responder_context)
    index_context = ExpectedContext(
        CHAIN_ID,
        SESSION_ID,
        ROSTER,
        ROLE,
        1,
        TERMS_HASH,
        RECOVERY_BINDING_HASH,
    )
    add("expected_index_mismatch", "Verify index zero when index one is expected.", statement, proof, index_context)

    output = []
    for name, description, case_statement, case_proof, case_context in cases:
        accepted, reason = verify(case_statement, case_proof, secp, case_context)
        output.append(
            {
                "name": name,
                "description": description,
                "accepted": accepted,
                "result": reason,
            }
        )
    accepted_names = [case["name"] for case in output if case["accepted"]]
    if accepted_names:
        raise AssertionError(f"negative cases unexpectedly accepted: {accepted_names}")
    return output


def exhaustive_single_bit_mutations(
    statement: bytes, proof: bytes, secp: Secp256k1
) -> dict[str, Any]:
    def scan(target_name: str, target: bytes) -> dict[str, Any]:
        rows = []
        accepted = []
        for offset in range(len(target)):
            rejected_mask = 0
            reasons = set()
            for bit in range(8):
                mask = 1 << bit
                mutated = mutate_byte(target, offset, mask)
                if target_name == "statement":
                    is_accepted, reason = verify(mutated, proof, secp)
                else:
                    is_accepted, reason = verify(statement, mutated, secp)
                if is_accepted:
                    accepted.append({"offset": offset, "bit": bit})
                else:
                    rejected_mask |= mask
                    reasons.add(reason)
            rows.append(
                {
                    "offset": offset,
                    "rejected_bit_mask": f"{rejected_mask:02x}",
                    "distinct_rejection_reasons": sorted(reasons),
                }
            )
        if accepted:
            raise AssertionError(
                f"{target_name} one-bit mutations unexpectedly accepted: {accepted}"
            )
        return {
            "bytes": len(target),
            "mutations_tested": len(target) * 8,
            "mutations_rejected": len(target) * 8,
            "accepted": accepted,
            "per_byte": rows,
        }

    statement_results = scan("statement", statement)
    proof_results = scan("proof", proof)
    return {
        "method": "Flip each of the eight individual bits at every byte offset, changing only one artifact at a time.",
        "statement": statement_results,
        "proof": proof_results,
        "total_mutations_tested": statement_results["mutations_tested"]
        + proof_results["mutations_tested"],
        "total_mutations_rejected": statement_results["mutations_rejected"]
        + proof_results["mutations_rejected"],
    }


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_artifacts(base_dir: Path) -> dict[str, bytes]:
    secp = Secp256k1()
    share_point = secp.scalar_point(SIGNING_SHARE)
    nonce_commitment = secp.scalar_point(EVIDENCE_NONCE)
    statement = encode_statement(share_point)
    context_digest, context_preimage = h_tag(STATEMENT_TAG, statement)
    challenge = derive_challenge(context_digest, share_point, nonce_commitment)
    challenge_scalar = challenge["scalar"]
    response = (EVIDENCE_NONCE + challenge_scalar * SIGNING_SHARE) % GROUP_ORDER
    response_bytes = scalar_bytes(response)
    proof = nonce_commitment + response_bytes

    accepted, reason = verify(statement, proof, secp)
    if not accepted:
        raise AssertionError(f"positive proof failed: {reason}")

    lhs = secp.scalar_point(response)
    rhs = secp.linear_combination(EVIDENCE_NONCE, share_point, challenge_scalar)
    rearranged_left = secp.linear_combination(
        response, share_point, (-challenge_scalar) % GROUP_ORDER
    )
    if not secp.points_equal(lhs, rhs):
        raise AssertionError("independent positive equation construction failed")
    if not secp.points_equal(rearranged_left, nonce_commitment):
        raise AssertionError("verifier rearranged equation failed")

    targeted = targeted_negative_cases(statement, proof, secp)
    exhaustive = exhaustive_single_bit_mutations(statement, proof, secp)

    vector = {
        "format": "DOM Share PoP V1 independent evidence vector",
        "encoding": "All byte strings are lowercase hexadecimal; scalars are 32-byte big-endian unless explicitly stated.",
        "inputs": {
            "chain_id": hex_bytes(CHAIN_ID),
            "session_id": hex_bytes(SESSION_ID),
            "roster_participant_ids": [hex_bytes(item) for item in ROSTER],
            "roster_order": "strictly ascending bytewise",
            "role": "Initiator",
            "role_code": f"{ROLE:02x}",
            "participant_index": PARTICIPANT_INDEX,
            "participant_index_le": PARTICIPANT_INDEX.to_bytes(2, "little").hex(),
            "signing_share_scalar": scalar_bytes(SIGNING_SHARE).hex(),
            "deterministic_evidence_nonce_scalar": scalar_bytes(EVIDENCE_NONCE).hex(),
            "terms_hash": hex_bytes(TERMS_HASH),
            "recovery_binding_hash": hex_bytes(RECOVERY_BINDING_HASH),
        },
        "statement": {
            "length": len(statement),
            "bytes": hex_bytes(statement),
            "fields": [
                {"name": "magic", "offset": 0, "size": 4, "bytes": statement[0:4].hex()},
                {"name": "version_le", "offset": 4, "size": 2, "bytes": statement[4:6].hex()},
                {"name": "chain_id", "offset": 6, "size": 32, "bytes": statement[6:38].hex()},
                {"name": "session_id", "offset": 38, "size": 32, "bytes": statement[38:70].hex()},
                {"name": "participant_id", "offset": 70, "size": 32, "bytes": statement[70:102].hex()},
                {"name": "role", "offset": 102, "size": 1, "bytes": statement[102:103].hex()},
                {"name": "participant_index_le", "offset": 103, "size": 2, "bytes": statement[103:105].hex()},
                {"name": "share_point", "offset": 105, "size": 33, "bytes": statement[105:138].hex()},
                {"name": "terms_hash", "offset": 138, "size": 32, "bytes": statement[138:170].hex()},
                {"name": "recovery_binding_hash", "offset": 170, "size": 32, "bytes": statement[170:202].hex()},
            ],
        },
        "points": {
            "share_point_R_i_compressed": share_point.hex(),
            "nonce_commitment_A_compressed": nonce_commitment.hex(),
        },
        "context": {
            "tag_ascii": STATEMENT_TAG,
            "tag_length": len(STATEMENT_TAG.encode("ascii")),
            "tag_length_u16_le": len(STATEMENT_TAG.encode("ascii")).to_bytes(2, "little").hex(),
            "data": statement.hex(),
            "preimage": context_preimage.hex(),
            "digest": context_digest.hex(),
        },
        "challenge": {
            "tag_ascii": CHALLENGE_TAG,
            "tag_length": len(CHALLENGE_TAG.encode("ascii")),
            "tag_length_u16_le": len(CHALLENGE_TAG.encode("ascii")).to_bytes(2, "little").hex(),
            "counter": challenge["counter"],
            "counter_u32_le": challenge["counter_le"].hex(),
            "input": challenge["input"].hex(),
            "d0_domain_byte": "00",
            "d0_data": challenge["d0_data"].hex(),
            "d0_preimage": challenge["d0_preimage"].hex(),
            "d0": challenge["d0"].hex(),
            "d1_domain_byte": "01",
            "d1_data": challenge["d1_data"].hex(),
            "d1_preimage": challenge["d1_preimage"].hex(),
            "d1": challenge["d1"].hex(),
            "wide_d0_then_d1": challenge["wide"].hex(),
            "reduction": "unsigned big-endian integer modulo secp256k1 group order q",
            "group_order_q": GROUP_ORDER.to_bytes(32, "big").hex(),
            "reduced_scalar_c": scalar_bytes(challenge_scalar).hex(),
        },
        "response": {
            "formula": "z = (a + c * r_i) mod q",
            "a": scalar_bytes(EVIDENCE_NONCE).hex(),
            "c": scalar_bytes(challenge_scalar).hex(),
            "r_i": scalar_bytes(SIGNING_SHARE).hex(),
            "c_times_r_i_mod_q": scalar_bytes((challenge_scalar * SIGNING_SHARE) % GROUP_ORDER).hex(),
            "z": response_bytes.hex(),
        },
        "proof": {
            "length": len(proof),
            "bytes": proof.hex(),
            "nonce_commitment_A": nonce_commitment.hex(),
            "response_z": response_bytes.hex(),
        },
    }

    verification = {
        "accepted": accepted,
        "result": reason,
        "equation": "zG == A + cR_i",
        "lhs_zG_compressed": lhs.hex(),
        "rhs_A_plus_cR_i_compressed": rhs.hex(),
        "lhs_equals_rhs": secp.points_equal(lhs, rhs),
        "verifier_equivalent_equation": "zG + (q-c)R_i == A",
        "rearranged_left_compressed": rearranged_left.hex(),
        "rearranged_right_A_compressed": nonce_commitment.hex(),
        "rearranged_sides_equal": secp.points_equal(rearranged_left, nonce_commitment),
        "response_zero_codec_policy": "zero is parsed as canonical; acceptance still requires the equation",
    }

    negatives = {
        "targeted": {
            "cases": targeted,
            "cases_tested": len(targeted),
            "cases_rejected": len(targeted),
        },
        "exhaustive_single_bit": exhaustive,
    }

    environment = {
        "generator_language": "Python",
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_full_version": sys.version.replace("\n", " "),
        "hash_implementation": "Python standard-library hashlib.blake2b(digest_size=32)",
        "hashlib_blake2b_module": hashlib.blake2b.__module__,
        "cryptography_version": cryptography.__version__,
        "elliptic_curve_backend": "OpenSSL EC API through cryptography.hazmat.bindings",
        "openssl_version": secp.openssl_version(),
    }

    artifacts: dict[str, bytes] = {
        "statement.bin": statement,
        "share-point.bin": share_point,
        "nonce-commitment.bin": nonce_commitment,
        "context-preimage.bin": context_preimage,
        "context-digest.bin": context_digest,
        "challenge-input.bin": challenge["input"],
        "challenge-counter-u32-le.bin": challenge["counter_le"],
        "challenge-d0-data.bin": challenge["d0_data"],
        "challenge-d0-preimage.bin": challenge["d0_preimage"],
        "challenge-d0.bin": challenge["d0"],
        "challenge-d1-data.bin": challenge["d1_data"],
        "challenge-d1-preimage.bin": challenge["d1_preimage"],
        "challenge-d1.bin": challenge["d1"],
        "challenge-wide.bin": challenge["wide"],
        "challenge-scalar.bin": scalar_bytes(challenge_scalar),
        "response.bin": response_bytes,
        "proof.bin": proof,
        "vector.json": json_bytes(vector),
        "verification.json": json_bytes(verification),
        "negative-mutations.json": json_bytes(negatives),
        "environment.json": json_bytes(environment),
    }

    manifest_names = [
        "PROVENANCE.md",
        "generate_share_pop_v1.py",
        *sorted(artifacts),
    ]
    manifest_lines = []
    for name in manifest_names:
        content = artifacts[name] if name in artifacts else (base_dir / name).read_bytes()
        manifest_lines.append(f"{hashlib.sha256(content).hexdigest()}  {name}\n")
    artifacts["SHA256SUMS"] = "".join(manifest_lines).encode("ascii")
    return artifacts


def run(mode: str) -> None:
    base_dir = Path(__file__).resolve().parent
    artifacts = build_artifacts(base_dir)
    if mode == "write":
        for name, content in artifacts.items():
            (base_dir / name).write_bytes(content)
        print(f"GENERATED artifacts={len(artifacts)}")
    else:
        mismatches = []
        for name, content in artifacts.items():
            path = base_dir / name
            if not path.is_file() or path.read_bytes() != content:
                mismatches.append(name)
        if mismatches:
            raise SystemExit("CHECK_FAILED mismatches=" + ",".join(mismatches))
        print(f"CHECK_OK artifacts={len(artifacts)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=("write", "check"),
        nargs="?",
        default="check",
        help="write deterministic artifacts or check existing artifacts",
    )
    args = parser.parse_args()
    run(args.mode)


if __name__ == "__main__":
    main()
