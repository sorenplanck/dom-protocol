//! Cross-language conformance against `contracts/test/vectors/f3_vectors.json`.
//!
//! The Solidity workstream emits that file from a Foundry test; this test
//! recomputes both halves in Rust and requires exact agreement. The derivation
//! is the load-bearing part of F3: if Rust and Solidity ever disagree by one
//! byte, every `lockId` diverges and funds lock against identifiers the other
//! side cannot address.
//!
//! When the file is absent (the Solidity workstream has not produced it yet)
//! the test reports that loudly and returns. When it is present it asserts
//! hard: there is no path in which a malformed or disagreeing vector file
//! results in a passing test.

use adapter_evm::binding::{
    adaptor_address_of_scalar, derive_binding, derive_lock_id, is_canonical_scalar,
};
use adapter_evm::{keccak256, LockTerms};
use serde_json::Value;
use std::path::PathBuf;

fn vectors_path() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/crates/adapters/evm
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..3 {
        p.pop();
    }
    p.join("contracts/test/vectors/f3_vectors.json")
}

// --- strict little helpers: a missing or malformed field is a hard failure ---

fn obj<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k)
        .unwrap_or_else(|| panic!("vector file is missing the required key `{k}`"))
}

fn hex_bytes(v: &Value, k: &str, want: usize) -> Vec<u8> {
    let s = obj(v, k)
        .as_str()
        .unwrap_or_else(|| panic!("`{k}` must be a 0x-prefixed string"));
    let body = s
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("`{k}` must be 0x-prefixed, got {s}"));
    let bytes = hex::decode(body).unwrap_or_else(|e| panic!("`{k}` is not hex: {e}"));
    assert_eq!(
        bytes.len(),
        want,
        "`{k}` must be {want} bytes, got {}",
        bytes.len()
    );
    bytes
}

fn b32(v: &Value, k: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(&hex_bytes(v, k, 32));
    o
}

fn addr(v: &Value, k: &str) -> [u8; 20] {
    let mut o = [0u8; 20];
    o.copy_from_slice(&hex_bytes(v, k, 20));
    o
}

/// A `uint256` that may arrive as a decimal string, a `0x` string, or a JSON
/// number. Anything else is a hard failure.
fn u256(v: &Value, k: &str) -> [u8; 32] {
    let raw = obj(v, k);
    let mut out = [0u8; 32];
    if let Some(n) = raw.as_u64() {
        out[24..].copy_from_slice(&n.to_be_bytes());
        return out;
    }
    let s = raw
        .as_str()
        .unwrap_or_else(|| panic!("`{k}` must be a number or a string, got {raw}"));
    if let Some(body) = s.strip_prefix("0x") {
        let bytes = hex::decode(format!("{:0>64}", body))
            .unwrap_or_else(|e| panic!("`{k}` is not hex: {e}"));
        assert_eq!(bytes.len(), 32, "`{k}` is wider than a uint256");
        out.copy_from_slice(&bytes);
        return out;
    }
    dec_to_u256(s, k)
}

/// Decimal string to a 32-byte big-endian word. Full 256-bit range: the vector
/// set deliberately includes `type(uint256).max`, which does not fit in `u128`.
fn dec_to_u256(s: &str, k: &str) -> [u8; 32] {
    assert!(!s.is_empty(), "`{k}` is empty");
    let mut out = [0u8; 32];
    for ch in s.chars() {
        let digit = ch
            .to_digit(10)
            .unwrap_or_else(|| panic!("`{k}` is not a decimal uint256: bad digit {ch:?}"));
        let mut carry = digit;
        for byte in out.iter_mut().rev() {
            let v = u32::from(*byte) * 10 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0, "`{k}` overflows a uint256");
    }
    out
}

fn u64_field(v: &Value, k: &str) -> u64 {
    let raw = obj(v, k);
    if let Some(n) = raw.as_u64() {
        return n;
    }
    let s = raw
        .as_str()
        .unwrap_or_else(|| panic!("`{k}` must be a number or a string, got {raw}"));
    match s.strip_prefix("0x") {
        Some(body) => u64::from_str_radix(body, 16)
            .unwrap_or_else(|e| panic!("`{k}` is not a hex uint64: {e}")),
        None => s
            .parse()
            .unwrap_or_else(|e| panic!("`{k}` is not a decimal uint64: {e}")),
    }
}

fn u8_field(v: &Value, k: &str) -> u8 {
    let n = u64_field(v, k);
    u8::try_from(n).unwrap_or_else(|_| panic!("`{k}` does not fit in a uint8: {n}"))
}

fn terms_of(v: &Value) -> LockTerms {
    let t = obj(v, "terms");
    LockTerms {
        dom_chain_id: b32(t, "domChainId"),
        direction: u8_field(t, "direction"),
        session_id: b32(t, "sessionId"),
        terms_hash: b32(t, "termsHash"),
        participants_hash: b32(t, "participantsHash"),
        asset: addr(t, "asset"),
        amount: u256(t, "amount"),
        beneficiary: addr(t, "beneficiary"),
        adaptor_address: addr(t, "adaptorAddress"),
        deadline: u64_field(t, "deadline"),
    }
}

#[test]
fn rust_agrees_with_solidity_on_every_cross_language_vector() {
    let path = vectors_path();
    if !path.exists() {
        eprintln!(
            "SKIPPED: {} is absent. It is produced by the Solidity workstream \
             (`forge test` writes it with vm.writeJson). This test asserts hard \
             once the file exists; it is NOT a silent pass.",
            path.display()
        );
        return;
    }

    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let doc: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()));

    // --- scalar vectors: address(t*G) ------------------------------------
    let scalars = obj(&doc, "scalarVectors")
        .as_array()
        .expect("`scalarVectors` must be an array")
        .clone();
    assert!(
        scalars.len() >= 16,
        "the spec requires at least 16 scalar vectors, found {}",
        scalars.len()
    );
    let mut saw_one = false;
    let mut saw_n_minus_one = false;
    let mut n_minus_one = adapter_evm::binding::SECP256K1_ORDER_BE;
    n_minus_one[31] -= 1;
    let mut one = [0u8; 32];
    one[31] = 1;

    for (i, v) in scalars.iter().enumerate() {
        let t = b32(v, "t");
        let expected = addr(v, "adaptorAddress");
        assert!(
            is_canonical_scalar(&t),
            "scalar vector {i} is not canonical for secp256k1"
        );
        let got = adaptor_address_of_scalar(&t)
            .unwrap_or_else(|e| panic!("scalar vector {i} failed to derive: {e:?}"));
        assert_eq!(
            got,
            expected,
            "scalar vector {i}: Rust derived {} but Solidity says {}",
            hex::encode(got),
            hex::encode(expected)
        );
        saw_one |= t == one;
        saw_n_minus_one |= t == n_minus_one;
    }
    assert!(saw_one, "the scalar vectors must include t = 1");
    assert!(saw_n_minus_one, "the scalar vectors must include t = n-1");

    // --- binding vectors: binding and lockId ------------------------------
    let bindings = obj(&doc, "bindingVectors")
        .as_array()
        .expect("`bindingVectors` must be an array")
        .clone();
    assert!(
        bindings.len() >= 8,
        "the spec requires at least 8 binding vectors, found {}",
        bindings.len()
    );

    let mut seen: Vec<([u8; 32], [u8; 32], [u8; 20])> = Vec::new();
    for (i, v) in bindings.iter().enumerate() {
        let chain_id = u64_field(v, "chainId");
        let contract = addr(v, "contract");
        let funder = addr(v, "funder");
        let terms = terms_of(v);
        let expected_binding = b32(v, "binding");
        let expected_lock_id = b32(v, "lockId");

        let binding = derive_binding(chain_id, &contract, &terms)
            .unwrap_or_else(|e| panic!("binding vector {i} failed to derive: {e:?}"));
        assert_eq!(
            binding,
            expected_binding,
            "binding vector {i}: Rust derived {} but Solidity says {}",
            hex::encode(binding),
            hex::encode(expected_binding)
        );

        let lock_id = derive_lock_id(&binding, &funder)
            .unwrap_or_else(|e| panic!("binding vector {i} failed to derive lockId: {e:?}"));
        assert_eq!(
            lock_id,
            expected_lock_id,
            "binding vector {i}: Rust derived lockId {} but Solidity says {}",
            hex::encode(lock_id),
            hex::encode(expected_lock_id)
        );

        seen.push((binding, lock_id, funder));
    }

    // Every `lockId` in the set must be distinct: the vectors vary one field at
    // a time, and two different vectors sharing an identifier would mean the
    // derivation is losing information somewhere.
    //
    // Two vectors *may* share a `binding` — that is exactly the anti-squatting
    // case from §1, same terms with a different `funder` — but only then.
    for (i, (bi, li, fi)) in seen.iter().enumerate() {
        for (j, (bj, lj, fj)) in seen.iter().enumerate().skip(i + 1) {
            assert_ne!(li, lj, "binding vectors {i} and {j} share a lockId");
            if bi == bj {
                assert_ne!(
                    fi, fj,
                    "binding vectors {i} and {j} share a binding with the same funder, \
                     so they are the same vector twice"
                );
            }
        }
    }
}

#[test]
fn the_domain_separators_match_the_frozen_preimages() {
    // Independent of the vector file: these two constants are what the Solidity
    // library hashes, and they are frozen by §1 of the interface spec.
    assert_eq!(
        adapter_evm::binding::binding_domain(),
        keccak256(b"DOM-Interop/ConditionLockV2/binding")
    );
    assert_eq!(
        adapter_evm::binding::lockid_domain(),
        keccak256(b"DOM-Interop/ConditionLockV2/lockId")
    );
    assert_eq!(adapter_evm::binding::BINDING_VERSION, 2);
}
