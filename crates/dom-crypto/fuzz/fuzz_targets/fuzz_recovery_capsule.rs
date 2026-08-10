#![no_main]

use dom_crypto::recovery::RecoveryCapsule;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = RecoveryCapsule::from_bytes(data);
});
