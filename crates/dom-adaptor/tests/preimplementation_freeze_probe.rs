//! Test-only probe for the already-authoritative DOM encoding/hash boundary.
//!
//! This is not an adaptor-signature or two-nonce implementation. Expected
//! digests were calculated independently with Python `hashlib.blake2b` over the
//! documented DOM tagged framing and are pinned in the repository vector file.

use dom_crypto::{blake2b_256_tagged, schnorr_challenge, PublicKey, Scalar};

const VECTOR_TEXT: &str =
    include_str!("../../../test-vectors/scriptless/hash-domains/DOM_G1A_BACKEND_FREEZE_V1.txt");

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex input has complete bytes");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("vector is ASCII");
            u8::from_str_radix(text, 16).expect("vector field is hexadecimal")
        })
        .collect()
}

#[test]
fn dom_tagged_hash_matches_independent_freeze_vectors() {
    for line in VECTOR_TEXT
        .lines()
        .filter(|line| line.starts_with("TAGGED|"))
    {
        let fields = line.split('|').collect::<Vec<_>>();
        assert_eq!(fields.len(), 4);
        let expected: [u8; 32] = decode_hex(fields[3]).try_into().expect("32-byte digest");
        assert_eq!(
            blake2b_256_tagged(fields[1], &decode_hex(fields[2])).as_bytes(),
            &expected
        );
        if fields[1] == "DOM:scriptless-sig-nonce-bind:v1" {
            assert!(
                Scalar::from_be_bytes(expected).is_ok(),
                "binding digest maps directly to a canonical nonzero BE scalar"
            );
        }
    }
}

#[test]
fn dom_challenge_matches_independent_freeze_vector() {
    let line = VECTOR_TEXT
        .lines()
        .find(|line| line.starts_with("CHALLENGE|"))
        .expect("challenge vector exists");
    let fields = line.split('|').collect::<Vec<_>>();
    assert_eq!(fields.len(), 6);
    let r: [u8; 33] = decode_hex(fields[1]).try_into().expect("R is 33 bytes");
    let x = PublicKey::from_compressed_bytes(&decode_hex(fields[2])).expect("X is canonical");
    let chain_id: [u8; 32] = decode_hex(fields[3])
        .try_into()
        .expect("chain id is 32 bytes");
    let message: [u8; 32] = decode_hex(fields[4])
        .try_into()
        .expect("message is 32 bytes");
    let expected: [u8; 32] = decode_hex(fields[5])
        .try_into()
        .expect("digest is 32 bytes");
    assert_eq!(
        schnorr_challenge(&r, &x, &chain_id, &message).as_bytes(),
        &expected
    );
}

#[test]
fn scalar_and_point_canonical_boundaries_are_explicit() {
    let mut one_be = [0u8; 32];
    one_be[31] = 1;
    let scalar = Scalar::from_be_bytes(one_be).expect("one is canonical");
    assert_eq!(scalar.to_be_bytes(), one_be);
    assert_eq!(scalar.as_le_bytes()[0], 1);
    assert!(Scalar::from_be_bytes([0u8; 32]).is_err());

    let generator =
        decode_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let point = PublicKey::from_compressed_bytes(&generator).expect("G is canonical SEC1");
    assert_eq!(point.to_compressed_bytes().as_slice(), generator.as_slice());
    assert!(PublicKey::from_compressed_bytes(&generator[1..]).is_err());
}
