//! Canonical properties of the DOMBTC codec (M.11.6):
//! P1 `decode(encode(x)) = x`, P2 `encode(decode(b)) = b`,
//! P3 trailing bytes always fail, P4 altering any binding prevents
//! acceptance — strengthened here to "altering ANY byte prevents
//! acceptance", which subsumes P4 for these artifacts.

use adapter_btc::codec::CanonicalBitcoinCodec;
use adapter_btc::roster::{BitcoinSignerRoleV1, ParticipantKeyRosterV1, ParticipantKeyV1};
use adapter_btc::types::{
    AdaptorPointV1, BitcoinSessionBindingV1, BtcAdaptorPreSignatureV1, NonceParityV1,
    PartialSignatureEnvelopeV1, PreSignatureEnvelopeV1, PublicNonceBytesV1, PublicNonceEnvelopeV1,
    RevealLegV1, SettlementDirectionV1, TapSighashV1, BTC_PROTOCOL_VERSION,
};
use proptest::prelude::*;

fn arb_32() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

/// A scalar guaranteed canonical: top byte zeroed keeps it far below n.
fn arb_scalar() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_map(|mut b| {
        b[0] = 0;
        b
    })
}

fn arb_point33() -> impl Strategy<Value = [u8; 33]> {
    (any::<bool>(), any::<[u8; 32]>()).prop_map(|(odd, x)| {
        let mut p = [0u8; 33];
        p[0] = if odd { 0x03 } else { 0x02 };
        p[1..].copy_from_slice(&x);
        p
    })
}

fn arb_nonce66() -> impl Strategy<Value = [u8; 66]> {
    (arb_point33(), arb_point33()).prop_map(|(a, b)| {
        let mut n = [0u8; 66];
        n[..33].copy_from_slice(&a);
        n[33..].copy_from_slice(&b);
        n
    })
}

prop_compose! {
    fn arb_roster()(
        id_a in arb_32(),
        id_b in arb_32(),
        key_a in arb_point33(),
        key_b in arb_point33(),
        maker_first in any::<bool>(),
    ) -> Option<ParticipantKeyRosterV1> {
        if id_a == id_b || key_a == key_b {
            return None;
        }
        let (role_a, role_b) = if maker_first {
            (BitcoinSignerRoleV1::Maker, BitcoinSignerRoleV1::Taker)
        } else {
            (BitcoinSignerRoleV1::Taker, BitcoinSignerRoleV1::Maker)
        };
        ParticipantKeyRosterV1::new([
            ParticipantKeyV1 { participant_id: id_a, role: role_a, compressed_key: key_a },
            ParticipantKeyV1 { participant_id: id_b, role: role_b, compressed_key: key_b },
        ])
        .ok()
    }
}

prop_compose! {
    fn arb_binding()(
        settlement_id in arb_32(),
        session_id in arb_32(),
        terms_hash in arb_32(),
        genesis in arb_32(),
        dom_chain in arb_32(),
        dir_dom in any::<bool>(),
        reveal_dom in any::<bool>(),
        roster_hash in arb_32(),
        adaptor in arb_point33(),
        funding in arb_32(),
        claim in arb_32(),
        refund in arb_32(),
    ) -> BitcoinSessionBindingV1 {
        BitcoinSessionBindingV1 {
            protocol_version: BTC_PROTOCOL_VERSION,
            settlement_id,
            session_id,
            terms_hash,
            bitcoin_genesis_hash: genesis,
            dom_chain_id: dom_chain,
            direction: if dir_dom {
                SettlementDirectionV1::DomToBitcoin
            } else {
                SettlementDirectionV1::BitcoinToDom
            },
            reveal_leg: if reveal_dom {
                RevealLegV1::DomFirst
            } else {
                RevealLegV1::BitcoinFirst
            },
            roster_hash,
            adaptor_point: AdaptorPointV1::from_bytes(adaptor).expect("valid form"),
            funding_template_hash: funding,
            claim_template_hash: claim,
            refund_template_hash: refund,
        }
    }
}

fn encode<T: CanonicalBitcoinCodec>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    value.encode_canonical(&mut out).expect("encodes");
    out
}

/// P1+P2+P3 and the every-byte-flip strengthening of P4, for any codec.
fn assert_canonical<T>(value: &T)
where
    T: CanonicalBitcoinCodec + PartialEq + core::fmt::Debug,
{
    let bytes = encode(value);
    assert!(bytes.len() <= T::MAX_ENCODED_LEN, "cap holds");

    // P1: decode(encode(x)) == x.
    let back = T::decode_canonical(&bytes).expect("canonical bytes decode");
    assert_eq!(&back, value);

    // P2: encode(decode(b)) == b.
    assert_eq!(encode(&back), bytes);

    // P3: one trailing byte always fails.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(T::decode_canonical(&trailing).is_err(), "trailing accepted");

    // P3 (prefix side): every strict prefix fails.
    for cut in 0..bytes.len() {
        assert!(
            T::decode_canonical(&bytes[..cut]).is_err(),
            "prefix of length {cut} accepted"
        );
    }

    // P4 strengthened: flipping any single byte prevents acceptance of
    // the artifact *as it was* — either the decode fails or the decoded
    // value differs from the original.
    for i in 0..bytes.len() {
        let mut mutated = bytes.clone();
        mutated[i] ^= 0x01;
        match T::decode_canonical(&mutated) {
            Err(_) => {}
            Ok(other) => {
                assert_ne!(&other, value, "byte {i} flip silently accepted");
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn canonical_roster(roster in arb_roster()) {
        if let Some(roster) = roster {
            assert_canonical(&roster);
        }
    }

    #[test]
    fn canonical_binding(binding in arb_binding()) {
        assert_canonical(&binding);
    }

    #[test]
    fn canonical_public_nonce_envelope(
        binding in arb_binding(),
        participant in arb_32(),
        nonce in arb_nonce66(),
    ) {
        let env = PublicNonceEnvelopeV1::new(
            binding.digest(),
            participant,
            PublicNonceBytesV1::from_bytes(nonce).expect("valid form"),
        );
        assert_canonical(&env);
    }

    #[test]
    fn canonical_partial_envelope(
        binding in arb_binding(),
        participant in arb_32(),
        nonce_digest in arb_32(),
        partial in arb_scalar(),
    ) {
        let env = PartialSignatureEnvelopeV1::new(
            binding.digest(),
            participant,
            nonce_digest,
            partial,
        ).expect("canonical scalar");
        assert_canonical(&env);
    }

    #[test]
    fn canonical_pre_signature_envelope(
        binding in arb_binding(),
        r_half in arb_32(),
        s_half in arb_scalar(),
        parity in any::<bool>(),
        adaptor in arb_point33(),
        sighash in arb_32(),
    ) {
        let mut pre = [0u8; 64];
        pre[..32].copy_from_slice(&r_half);
        pre[32..].copy_from_slice(&s_half);
        let env = PreSignatureEnvelopeV1::new(
            binding.digest(),
            BtcAdaptorPreSignatureV1(pre),
            if parity { NonceParityV1::Odd } else { NonceParityV1::Even },
            AdaptorPointV1::from_bytes(adaptor).expect("valid form"),
            TapSighashV1(sighash),
        ).expect("canonical pre-signature");
        assert_canonical(&env);
    }
}

// Deterministic adversarial cases that proptest may not hit.
mod adversarial {
    use super::*;
    use adapter_btc::error::CodecError;
    use adapter_btc::scalar::SECP256K1_ORDER_BE;

    fn sample_binding_bytes() -> (BitcoinSessionBindingV1, Vec<u8>) {
        let binding = BitcoinSessionBindingV1 {
            protocol_version: BTC_PROTOCOL_VERSION,
            settlement_id: [1; 32],
            session_id: [2; 32],
            terms_hash: [3; 32],
            bitcoin_genesis_hash: [4; 32],
            dom_chain_id: [5; 32],
            direction: SettlementDirectionV1::DomToBitcoin,
            reveal_leg: RevealLegV1::BitcoinFirst,
            roster_hash: [6; 32],
            adaptor_point: AdaptorPointV1::from_bytes({
                let mut p = [7u8; 33];
                p[0] = 0x02;
                p
            })
            .expect("valid form"),
            funding_template_hash: [8; 32],
            claim_template_hash: [9; 32],
            refund_template_hash: [10; 32],
        };
        let bytes = encode(&binding);
        (binding, bytes)
    }

    #[test]
    fn wrong_magic_version_kind_fail() {
        let (_, bytes) = sample_binding_bytes();
        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            BitcoinSessionBindingV1::decode_canonical(&bad_magic).unwrap_err(),
            CodecError::BadMagic
        );
        let mut bad_version = bytes.clone();
        bad_version[7] = 9;
        assert_eq!(
            BitcoinSessionBindingV1::decode_canonical(&bad_version).unwrap_err(),
            CodecError::UnsupportedVersion
        );
        let mut bad_kind = bytes.clone();
        bad_kind[9] = 0x7f;
        assert_eq!(
            BitcoinSessionBindingV1::decode_canonical(&bad_kind).unwrap_err(),
            CodecError::KindMismatch
        );
        // A valid OTHER kind is also a kind mismatch, not a parse of the
        // wrong type (artifacts never cross-decode).
        let mut other_kind = bytes;
        other_kind[9] = 0x03;
        assert!(BitcoinSessionBindingV1::decode_canonical(&other_kind).is_err());
    }

    #[test]
    fn over_cap_fails_before_parsing() {
        let (_, bytes) = sample_binding_bytes();
        let mut oversized = bytes;
        oversized.extend_from_slice(&[0u8; 64]);
        assert_eq!(
            BitcoinSessionBindingV1::decode_canonical(&oversized).unwrap_err(),
            CodecError::OverCap
        );
    }

    #[test]
    fn non_canonical_partial_scalar_fails() {
        let err = PartialSignatureEnvelopeV1::new([0; 32], [1; 32], [2; 32], SECP256K1_ORDER_BE)
            .unwrap_err();
        assert_eq!(
            err,
            CodecError::InvalidField {
                field: "partial_signature"
            }
        );
    }

    #[test]
    fn non_canonical_pre_signature_scalar_fails() {
        let mut pre = [0u8; 64];
        pre[32..].copy_from_slice(&SECP256K1_ORDER_BE);
        let err = PreSignatureEnvelopeV1::new(
            [0; 32],
            BtcAdaptorPreSignatureV1(pre),
            NonceParityV1::Even,
            AdaptorPointV1::from_bytes({
                let mut p = [1u8; 33];
                p[0] = 0x02;
                p
            })
            .expect("valid form"),
            TapSighashV1([2; 32]),
        )
        .unwrap_err();
        assert_eq!(
            err,
            CodecError::InvalidField {
                field: "pre_signature"
            }
        );
    }

    #[test]
    fn invalid_point_prefix_fails() {
        assert!(AdaptorPointV1::from_bytes([0x04u8; 33]).is_err());
        assert!(AdaptorPointV1::from_bytes([0x00u8; 33]).is_err());
        let mut nonce = [0u8; 66];
        nonce[0] = 0x02;
        nonce[33] = 0x05;
        assert!(PublicNonceBytesV1::from_bytes(nonce).is_err());
    }
}
