#![no_main]
//! Exercise the OS-randomized production nonce-derivation boundary.

use dom_crypto::{ScriptlessNonceDerivationV1, ScriptlessSecretScalar};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 512 {
        return;
    }
    let signing_share = ScriptlessSecretScalar::from_be_bytes({
        let mut scalar = [0u8; 32];
        scalar[31] = 1;
        scalar
    })
    .expect("fixed fuzz signing share is canonical");
    if let Ok(derivation) = ScriptlessNonceDerivationV1::from_os_rng() {
        let _ = derivation.derive_pair(&signing_share, data);
    }
});
