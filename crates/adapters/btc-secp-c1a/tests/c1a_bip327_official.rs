//! C1a — official BIP327 vectors (Annex M M.11.1).
//!
//! Runs the COMPLETE test suite of the pinned upstream revision, which
//! embeds the official BIP327 vector families (auto-generated upstream
//! from the vectors published with BIP327) and executes them inside
//! `run_musig_tests`: key aggregation (valid + error), nonce generation,
//! nonce aggregation, sign/verify (including error and verify-fail
//! cases, via upstream's own secnonce-loading test helper), tweaks and
//! signature aggregation. Nothing is adapted, filtered or reordered:
//! the vector-running functions are upstream's, compiled from the pin.
//!
//! A `CHECK` failure aborts the process — a normal exit with 0 IS the
//! pass. The seed below is fixed so the randomized portions of the
//! suite are reproducible; the vector families do not depend on it.
//!
//! Known upstream deviation, recorded for the C1a report (M.11.1 demands
//! this is documented, never silently skipped): upstream itself skips
//! `sign_error_case[0]` of the sign/verify vectors ("signing key does
//! not belong to any pubkey"), because the C API treats that misuse as
//! caller error rather than a detectable failure. The skip is upstream
//! code at the pinned revision, not a local adaptation.

/// Deterministic seed recorded in the F5 evidence.
const C1A_SEED: &str = "d0b1c001d0b1c001d0b1c001d0b1c001d0b1c001d0b1c001d0b1c001d0b1c001";

#[test]
fn c1a_upstream_suite_with_official_bip327_vectors() {
    let code = btc_secp_c1a::run_upstream_suite(1, C1A_SEED);
    assert_eq!(code, 0, "upstream suite exited nonzero");
}
