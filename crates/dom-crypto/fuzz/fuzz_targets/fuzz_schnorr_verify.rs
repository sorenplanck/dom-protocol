#![no_main]
//! Fuzz target: schnorr_verify with attacker-controlled signature + public key + message.
//!
//! Invariant: verification of arbitrary inputs must NEVER panic — must return
//! Ok(false), Ok(true) (probabilistically impossible without forge), or Err.
use libfuzzer_sys::fuzz_target;
use dom_crypto::keys::PublicKey;
use dom_crypto::schnorr::{schnorr_verify, SchnorrSignature};

fuzz_target!(|data: &[u8]| {
    if data.len() < 65 + 33 + 32 {
        return;
    }
    let sig = match SchnorrSignature::from_bytes(&data[..65]) {
        Ok(s) => s,
        Err(_) => return,
    };
    let pk_bytes: [u8; 33] = match data[65..65 + 33].try_into() {
        Ok(b) => b,
        Err(_) => return,
    };
    let pk = match PublicKey::from_compressed_bytes(&pk_bytes) {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut chain_id = [0u8; 32];
    chain_id.copy_from_slice(&data[65 + 33..65 + 33 + 32]);
    let message = &data[65 + 33 + 32..];
    let _ = schnorr_verify(&sig, &pk, &chain_id, message);
});
