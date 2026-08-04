#![no_main]
//! Fuzz all currently implemented canonical G1a message and primitive parsers.

use dom_adaptor::{NonceCommitmentV1, NonceRevealV1, PartialSignatureV1, PurposeV1};
use dom_crypto::{PartialSig, PublicKey, SchnorrSignature};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(byte) = data.first() {
        let _ = PurposeV1::try_from(*byte);
    }
    let _ = NonceCommitmentV1::from_bytes(data);
    let _ = NonceRevealV1::from_bytes(data);
    let _ = PartialSignatureV1::from_bytes(data);
    let _ = PublicKey::from_compressed_bytes(data);
    let _ = PartialSig::from_bytes(data);
    let _ = SchnorrSignature::from_bytes(data);
});
