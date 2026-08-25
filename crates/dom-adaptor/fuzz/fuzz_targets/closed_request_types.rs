#![no_main]
//! Exercise the four closed reservation and computation request constructors.

use dom_adaptor::fuzz_closed_request_types_v1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_closed_request_types_v1(data);
});
