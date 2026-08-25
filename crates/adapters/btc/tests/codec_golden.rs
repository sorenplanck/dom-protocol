//! Golden vectors of the DOMBTC codec (M.5.3): the canonical encodings
//! and digests below are frozen byte for byte. A change in any of them is
//! a wire break and requires a new kind/version, never an edit here.

use adapter_btc::codec::{f5_digest, CanonicalBitcoinCodec};
use adapter_btc::roster::{BitcoinSignerRoleV1, ParticipantKeyRosterV1, ParticipantKeyV1};
use adapter_btc::types::{
    AdaptorPointV1, BitcoinSessionBindingV1, BtcAdaptorPreSignatureV1, NonceParityV1,
    PartialSignatureEnvelopeV1, PreSignatureEnvelopeV1, PublicNonceBytesV1, PublicNonceEnvelopeV1,
    RevealLegV1, SettlementDirectionV1, TapSighashV1, BTC_PROTOCOL_VERSION,
};

fn le_pattern<const N: usize>(seed: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    out
}

fn sample_roster() -> ParticipantKeyRosterV1 {
    let mut key_a = [0u8; 33];
    key_a[0] = 0x02;
    key_a[1..].copy_from_slice(&le_pattern::<32>(0x10));
    let mut key_b = [0u8; 33];
    key_b[0] = 0x03;
    key_b[1..].copy_from_slice(&le_pattern::<32>(0x60));
    ParticipantKeyRosterV1::new([
        ParticipantKeyV1 {
            participant_id: le_pattern::<32>(0xa0),
            role: BitcoinSignerRoleV1::Maker,
            compressed_key: key_a,
        },
        ParticipantKeyV1 {
            participant_id: le_pattern::<32>(0xb0),
            role: BitcoinSignerRoleV1::Taker,
            compressed_key: key_b,
        },
    ])
    .expect("valid roster")
}

fn sample_adaptor_point() -> AdaptorPointV1 {
    let mut t = [0u8; 33];
    t[0] = 0x02;
    t[1..].copy_from_slice(&le_pattern::<32>(0xc0));
    AdaptorPointV1::from_bytes(t).expect("valid point form")
}

fn sample_binding() -> BitcoinSessionBindingV1 {
    BitcoinSessionBindingV1 {
        protocol_version: BTC_PROTOCOL_VERSION,
        settlement_id: le_pattern::<32>(0x01),
        session_id: le_pattern::<32>(0x02),
        terms_hash: le_pattern::<32>(0x03),
        bitcoin_genesis_hash: le_pattern::<32>(0x04),
        dom_chain_id: le_pattern::<32>(0x05),
        direction: SettlementDirectionV1::DomToBitcoin,
        reveal_leg: RevealLegV1::BitcoinFirst,
        roster_hash: sample_roster()
            .roster_hash()
            .expect("sample roster is valid"),
        adaptor_point: sample_adaptor_point(),
        funding_template_hash: le_pattern::<32>(0x06),
        claim_template_hash: le_pattern::<32>(0x07),
        refund_template_hash: le_pattern::<32>(0x08),
    }
}

fn sample_public_nonce() -> PublicNonceBytesV1 {
    let mut nonce = [0u8; 66];
    nonce[0] = 0x02;
    nonce[1..33].copy_from_slice(&le_pattern::<32>(0x20));
    nonce[33] = 0x03;
    nonce[34..].copy_from_slice(&le_pattern::<32>(0x40));
    PublicNonceBytesV1::from_bytes(nonce).expect("valid nonce form")
}

fn encode<T: CanonicalBitcoinCodec>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    value.encode_canonical(&mut out).expect("encodes");
    assert!(out.len() <= T::MAX_ENCODED_LEN);
    out
}

// The frozen goldens. Generated once from the implementation above and
// reviewed; from here on they only ever break on purpose.
mod frozen {
    pub const ROSTER_HEX: &str = "444f4d425443000100020001a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0102101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2fb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf0203606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";
    pub const ROSTER_HASH_HEX: &str =
        "c4040722e8fd5b95cfd06cba5c2cb79c833755e03ab82a074bf5c14852731f41";
    pub const BINDING_HEX: &str = "444f4d4254430001000100010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223240102c4040722e8fd5b95cfd06cba5c2cb79c833755e03ab82a074bf5c14852731f4102c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252608090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627";
    pub const BINDING_DIGEST_HEX: &str =
        "dbf6e61e1d7f9512a19900bfca80bc96c1b4adf446bc10d9dda234d0babb4cf7";
    pub const NONCE_ENVELOPE_HEX: &str = "444f4d42544300010003dbf6e61e1d7f9512a19900bfca80bc96c1b4adf446bc10d9dda234d0babb4cf7a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf02202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f03404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fd618692cce4718ed36361955784c22a96c629365758bb6b1b03b2978b8a090aa";
    pub const PARTIAL_ENVELOPE_HEX: &str = "444f4d42544300010004dbf6e61e1d7f9512a19900bfca80bc96c1b4adf446bc10d9dda234d0babb4cf7a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf9eef19795a2d4be1ea182ec3ef5baf731d9711065db97df6c3afa5549d070a90005152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f3aebad0d5e09e63134f34a6fb6c5242e29a32eeaee61ff76db6ba73c557660fe";
    pub const PRE_SIG_ENVELOPE_HEX: &str = "444f4d42544300010005dbf6e61e1d7f9512a19900bfca80bc96c1b4adf446bc10d9dda234d0babb4cf7707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f007172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f0102c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf1bb43f02e921a586eb3882aea386ad77be8124b7e0562d58029de86cc76a7afc";
}

#[test]
fn golden_roster_encoding_and_hash() {
    let roster = sample_roster();
    let bytes = encode(&roster);
    assert_eq!(hex::encode(&bytes), frozen::ROSTER_HEX);
    assert_eq!(
        hex::encode(roster.roster_hash().expect("sample roster is valid")),
        frozen::ROSTER_HASH_HEX
    );
    let back = ParticipantKeyRosterV1::decode_canonical(&bytes).expect("decodes");
    assert_eq!(back, roster);
}

#[test]
fn golden_binding_encoding_and_digest() {
    let binding = sample_binding();
    let bytes = encode(&binding);
    assert_eq!(hex::encode(&bytes), frozen::BINDING_HEX);
    assert_eq!(hex::encode(binding.digest()), frozen::BINDING_DIGEST_HEX);
    let back = BitcoinSessionBindingV1::decode_canonical(&bytes).expect("decodes");
    assert_eq!(back, binding);
}

#[test]
fn golden_public_nonce_envelope() {
    let env = PublicNonceEnvelopeV1::new(
        sample_binding().digest(),
        le_pattern::<32>(0xa0),
        sample_public_nonce(),
    );
    let bytes = encode(&env);
    assert_eq!(hex::encode(&bytes), frozen::NONCE_ENVELOPE_HEX);
    let back = PublicNonceEnvelopeV1::decode_canonical(&bytes).expect("decodes");
    assert_eq!(back, env);
}

#[test]
fn golden_partial_signature_envelope() {
    let nonce_env = PublicNonceEnvelopeV1::new(
        sample_binding().digest(),
        le_pattern::<32>(0xa0),
        sample_public_nonce(),
    );
    let mut partial = [0u8; 32];
    // A canonical scalar comfortably below n.
    partial[1..].copy_from_slice(&le_pattern::<31>(0x51));
    let env = PartialSignatureEnvelopeV1::new(
        sample_binding().digest(),
        le_pattern::<32>(0xa0),
        f5_digest(PublicNonceEnvelopeV1::KIND, &encode(&nonce_env)),
        partial,
    )
    .expect("canonical partial");
    let bytes = encode(&env);
    assert_eq!(hex::encode(&bytes), frozen::PARTIAL_ENVELOPE_HEX);
    let back = PartialSignatureEnvelopeV1::decode_canonical(&bytes).expect("decodes");
    assert_eq!(back, env);
}

#[test]
fn golden_pre_signature_envelope() {
    let mut pre = [0u8; 64];
    pre[..32].copy_from_slice(&le_pattern::<32>(0x70));
    // ŝ half kept canonical (below n) by zeroing the first byte.
    pre[33..].copy_from_slice(&le_pattern::<31>(0x71));
    let env = PreSignatureEnvelopeV1::new(
        sample_binding().digest(),
        BtcAdaptorPreSignatureV1(pre),
        NonceParityV1::Odd,
        sample_adaptor_point(),
        TapSighashV1(le_pattern::<32>(0x90)),
    )
    .expect("canonical pre-signature");
    let bytes = encode(&env);
    assert_eq!(hex::encode(&bytes), frozen::PRE_SIG_ENVELOPE_HEX);
    let back = PreSignatureEnvelopeV1::decode_canonical(&bytes).expect("decodes");
    assert_eq!(back, env);
}

/// One-time generator: run with `--ignored --nocapture` to print the hex
/// pairs above when the wire is *intentionally* revised (new version).
#[test]
#[ignore]
fn print_goldens() {
    let roster = sample_roster();
    println!("ROSTER_HEX={}", hex::encode(encode(&roster)));
    println!(
        "ROSTER_HASH_HEX={}",
        hex::encode(roster.roster_hash().expect("sample roster is valid"))
    );
    let binding = sample_binding();
    println!("BINDING_HEX={}", hex::encode(encode(&binding)));
    println!("BINDING_DIGEST_HEX={}", hex::encode(binding.digest()));
    let nonce_env = PublicNonceEnvelopeV1::new(
        binding.digest(),
        le_pattern::<32>(0xa0),
        sample_public_nonce(),
    );
    println!("NONCE_ENVELOPE_HEX={}", hex::encode(encode(&nonce_env)));
    let mut partial = [0u8; 32];
    partial[1..].copy_from_slice(&le_pattern::<31>(0x51));
    let partial_env = PartialSignatureEnvelopeV1::new(
        binding.digest(),
        le_pattern::<32>(0xa0),
        f5_digest(PublicNonceEnvelopeV1::KIND, &encode(&nonce_env)),
        partial,
    )
    .expect("canonical partial");
    println!("PARTIAL_ENVELOPE_HEX={}", hex::encode(encode(&partial_env)));
    let mut pre = [0u8; 64];
    pre[..32].copy_from_slice(&le_pattern::<32>(0x70));
    pre[33..].copy_from_slice(&le_pattern::<31>(0x71));
    let pre_env = PreSignatureEnvelopeV1::new(
        binding.digest(),
        BtcAdaptorPreSignatureV1(pre),
        NonceParityV1::Odd,
        sample_adaptor_point(),
        TapSighashV1(le_pattern::<32>(0x90)),
    )
    .expect("canonical pre-signature");
    println!("PRE_SIG_ENVELOPE_HEX={}", hex::encode(encode(&pre_env)));
}
