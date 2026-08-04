#![no_main]
//! Fuzz all currently implemented canonical G1a message and primitive parsers.

use dom_adaptor::{
    DirectionV1, NonceCommitmentV1, NonceRevealV1, PartialSignatureV1, PurposeV1,
    SessionContextV1, SigningPhaseV1,
};
use dom_crypto::{PartialSig, PublicKey, SchnorrSignature, ScriptlessSecretScalar};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(byte) = data.first() {
        let _ = PurposeV1::try_from(*byte);
        let _ = DirectionV1::try_from(*byte);
    }
    if data.len() >= 2 {
        let _ = SigningPhaseV1::try_from(u16::from_le_bytes([data[0], data[1]]));
    }
    let _ = NonceCommitmentV1::from_bytes(data);
    let _ = NonceRevealV1::from_bytes(data);
    let _ = PartialSignatureV1::from_bytes(data);
    let _ = PublicKey::from_compressed_bytes(data);
    let _ = PartialSig::from_bytes(data);
    let _ = SchnorrSignature::from_bytes(data);
    let signing_share = ScriptlessSecretScalar::from_be_bytes([0x07; 32])
        .expect("fixed fuzz harness scalar is canonical");
    let _ = SessionContextV1::from_bytes(data, &[0xaa; 32], &signing_share);
});
