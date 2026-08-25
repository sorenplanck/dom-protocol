#![no_main]
//! Exercise the bounded DSC1 parser and authenticated signing-round acceptance path.

use dom_adaptor::fuzz_dsc1_signing_round_acceptance_v1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_dsc1_signing_round_acceptance_v1(data);
});
