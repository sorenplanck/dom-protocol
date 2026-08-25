#![no_main]
//! Fuzz the exact-length adaptor pre-signature parser.

use dom_adaptor::AdaptorPreSignatureV1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = AdaptorPreSignatureV1::from_bytes(data);
});
