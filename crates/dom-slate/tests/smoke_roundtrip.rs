//! Sanity: a balancing round-trip must finalize cleanly. This is the harness
//! the FIX-022 / FIX-008 reproducers tamper with, so it must be green first.

mod common;

#[test]
fn full_roundtrip_with_change_finalizes() {
    let tx = common::full_roundtrip(1_000, 10, 500);
    assert_eq!(tx.inputs.len(), 1);
    // change output + recipient output
    assert_eq!(tx.outputs.len(), 2);
    assert_eq!(tx.kernels.len(), 1);
}

#[test]
fn full_roundtrip_no_change_finalizes() {
    let tx = common::full_roundtrip(2_000, 20, 0);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
}
