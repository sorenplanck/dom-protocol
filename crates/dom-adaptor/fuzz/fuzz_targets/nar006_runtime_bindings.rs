#![no_main]
//! Exercise NAR-006 recovered spent-artifact binding and mutation rejection.

use dom_adaptor::fuzz_nar006_runtime_bindings_v1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_nar006_runtime_bindings_v1(data);
});
