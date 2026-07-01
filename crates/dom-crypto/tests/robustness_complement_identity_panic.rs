//! FABLE5 robustness PoC — `bp2_verify` must not panic on a crafted output
//! commitment equal to `MAX_PROVABLE_VALUE * H`.
//!
//! `bp2_verify` derives the bounded-aggregate complement
//! `C' = MAX_PROVABLE_VALUE*H - C` (see `derive_complement_commitment` →
//! `Commitment::sub`). When `C == MAX_PROVABLE_VALUE*H`, `C'` is the point at
//! infinity, whose SEC1 compressed encoding is a single byte. `Commitment::sub`
//! does `copy_from_slice(encoded.as_bytes())` into a `[0u8; 33]`, which panics
//! on the length mismatch. With `panic = "abort"` (release profile) this aborts
//! the whole node process. The commitment is a single, publicly computable
//! curve point, so any peer can embed it in a transaction/coinbase output and
//! crash every validating node (`bp2_verify` is called from
//! `dom-consensus` coinbase + range-proof validation and `dom-slate::finalize`).
//!
//! A robust verifier must return `Ok(false)`/`Err(_)` — never panic.

use dom_crypto::bp2_verify;
use dom_crypto::pedersen::{BlindingFactor, Commitment};

const MAX_PROVABLE_VALUE: u64 = (1u64 << 52) - 1;
const SINGLE_BULLETPROOF_SIZE: usize = 739;

/// Build `MAX_PROVABLE_VALUE * H` through the public API only:
/// `commit(MAX, r) = MAX*H + r*G` and `commit(0, r) = r*G`, so their
/// difference is `MAX*H` (the blinding cancels).
fn max_times_h() -> Commitment {
    let r = BlindingFactor::from_bytes([0x11u8; 32]).expect("blinding");
    let c_max = Commitment::commit(MAX_PROVABLE_VALUE, &r);
    let c_zero = Commitment::commit(0, &r);
    c_max
        .sub(&c_zero)
        .expect("MAX*H is a valid (non-identity) point")
}

#[test]
fn bp2_verify_does_not_panic_on_max_times_h_commitment() {
    let max_h = max_times_h();

    // Sanity: MAX*H is itself a valid, accepted commitment encoding — the
    // degenerate case is the *complement*, not this input.
    assert!(
        Commitment::from_compressed_bytes(max_h.as_bytes()).is_ok(),
        "MAX*H must be a well-formed commitment that the parser accepts"
    );

    // Length-valid proof so we pass the size gate and reach complement
    // derivation. The bytes need not be a real proof — the panic happens
    // before the FFI verify.
    let proof = vec![0u8; SINGLE_BULLETPROOF_SIZE];

    // CONTRACT: a verifier must reject, not panic/abort.
    let res = bp2_verify(max_h.as_bytes(), &proof);
    assert!(
        matches!(res, Ok(false) | Err(_)),
        "bp2_verify must fail closed on the MAX*H commitment, got {res:?}"
    );
}
