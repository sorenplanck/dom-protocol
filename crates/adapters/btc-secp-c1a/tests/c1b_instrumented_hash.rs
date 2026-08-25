//! C1b — instrumented semantics of tagged-hash integers ≥ n (M.11.2).
//!
//! Hash ≥ n cases are NOT sought by grinding (probability ~2^-128); the
//! harness injects the post-hash 256-bit integer directly and freezes
//! the expected operation. The two semantics are opposite, and natural
//! (C1a) tests cannot distinguish them:
//!
//! - `tagged_hash("KeyAgg coefficient", …) ≥ n` → the integer is
//!   interpreted and REDUCED modulo n; never rejected merely for
//!   overflowing n. Probed through the library's scalar interpretation
//!   (`scalar_set_b32`), which is exactly what the KeyAgg coefficient
//!   uses at the pinned revision.
//! - `tagged_hash("TapTweak", …) ≥ n` → ApplyTweak FAILS; the value is
//!   never reduced. Probed at the x-only tweak-add boundary — the same
//!   API the production wrapper calls with the TapTweak hash it
//!   computed (the tweak32 argument IS the injection point).
//!
//! The fixtures below freeze, in hex: the injected integer, the expected
//! operation and the expected result (M.11.2). The preimages are
//! symbolic on purpose: the harness does not implement SHA-256 and no
//! preimage of these integers is known — that is the point.
//!
//! C1b is formally excluded from the C3 differential (M.11.4).

/// One frozen injection fixture.
struct C1bFixture {
    /// Symbolic name recorded in the evidence.
    name: &'static str,
    /// The injected post-hash integer, big-endian hex.
    injected: &'static str,
    /// Expected `scalar_set_b32` output (reduction mod n), hex.
    expected_reduced: &'static str,
    /// Whether the reduction must report overflow (integer ≥ n).
    expected_overflow: bool,
}

/// Frozen fixtures. `n` is the secp256k1 group order.
const FIXTURES: &[C1bFixture] = &[
    C1bFixture {
        name: "exactly-n",
        injected: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        expected_reduced: "0000000000000000000000000000000000000000000000000000000000000000",
        expected_overflow: true,
    },
    C1bFixture {
        name: "n-plus-1",
        injected: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
        expected_reduced: "0000000000000000000000000000000000000000000000000000000000000001",
        expected_overflow: true,
    },
    C1bFixture {
        name: "all-ones",
        injected: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        expected_reduced: "000000000000000000000000000000014551231950b75fc4402da1732fc9bebe",
        expected_overflow: true,
    },
    C1bFixture {
        name: "n-plus-pattern",
        injected: "fffffffffffffffffffffffffffffffebaaedce6af48a03c9e801d7bd0f7412f",
        expected_reduced: "000000000000000000000000000000000000000000000000deadbeef00c0ffee",
        expected_overflow: true,
    },
    C1bFixture {
        name: "n-minus-1-control",
        injected: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        expected_reduced: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        expected_overflow: false,
    },
];

fn decode32(hex_str: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&hex::decode(hex_str).expect("fixture hex"));
    out
}

#[test]
fn c1b_keyagg_coefficient_semantics_reduce_mod_n() {
    for fixture in FIXTURES {
        let (reduced, overflow) =
            btc_secp_c1a::scalar_set_b32_semantics(decode32(fixture.injected));
        assert_eq!(
            hex::encode(reduced),
            fixture.expected_reduced,
            "fixture {}",
            fixture.name
        );
        assert_eq!(
            overflow, fixture.expected_overflow,
            "fixture {}",
            fixture.name
        );
    }
}

#[test]
fn c1b_taptweak_semantics_fail_without_reduction() {
    for fixture in FIXTURES {
        let accepts = btc_secp_c1a::xonly_tweak_add_accepts(decode32(fixture.injected));
        if fixture.expected_overflow {
            // A TapTweak ≥ n must FAIL at ApplyTweak — if the library
            // reduced it, the tweak would succeed with a silently
            // different key, which is exactly the disaster C1b guards
            // against.
            assert!(!accepts, "tweak ≥ n was accepted: fixture {}", fixture.name);
        } else {
            assert!(
                accepts,
                "canonical tweak rejected: fixture {}",
                fixture.name
            );
        }
    }
}
