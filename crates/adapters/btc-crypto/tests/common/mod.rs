//! Shared TEST-ONLY-NON-PRODUCTION helpers for the C2/C3/C4 conformance
//! suites. Every secret here is synthetic; production secrets are born in
//! the vault and never appear in fixtures (M.11.3).

#![allow(dead_code)]

use btc_crypto::SecpContext;

/// `n`, the secp256k1 group order, big-endian.
pub const ORDER_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// The scalar `1`.
pub fn scalar_one() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = 1;
    s
}

/// The scalar `n - 1`.
pub fn scalar_n_minus_1() -> [u8; 32] {
    let mut s = ORDER_BE;
    s[31] -= 1;
    s
}

/// Derives a valid compressed pubkey from a 32-byte secret via the pinned
/// sys crate directly (no public pubkey-create on the safe backend). The
/// returned key parses in the safe backend.
pub fn compressed_pubkey(secret: &[u8; 32]) -> Option<[u8; 33]> {
    use btc_secp_sys::*;
    let size = unsafe { secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE) };
    let layout = std::alloc::Layout::from_size_align(size, 16).unwrap();
    let mem = unsafe { std::alloc::alloc(layout) };
    let c = unsafe { secp256k1_context_preallocated_create(mem.cast(), SECP256K1_CONTEXT_NONE) };
    let mut pk = secp256k1_pubkey { data: [0; 64] };
    let ok = unsafe { secp256k1_ec_pubkey_create(c, &mut pk, secret.as_ptr()) };
    let out = if ok == 1 {
        let mut out = [0u8; 33];
        let mut len = 33usize;
        let s = unsafe {
            secp256k1_ec_pubkey_serialize(
                c,
                out.as_mut_ptr(),
                &mut len,
                &pk,
                SECP256K1_EC_COMPRESSED,
            )
        };
        if s == 1 {
            Some(out)
        } else {
            None
        }
    } else {
        None
    };
    unsafe {
        secp256k1_context_preallocated_destroy(c);
        std::alloc::dealloc(mem, layout);
    }
    out
}

/// Deterministic 32-byte value from a label and counter (no RNG — keeps
/// the vectors reproducible; `Math.random`-style entropy is banned in this
/// environment and would defeat frozen vectors anyway).
pub fn seeded(label: u8, counter: u32) -> [u8; 32] {
    let ctx = SecpContext::new(&[0x11; 32]);
    let mut msg = [0u8; 8];
    msg[0] = label;
    msg[4..8].copy_from_slice(&counter.to_be_bytes());
    ctx.tagged_sha256(b"DOM-INTEROP/BTC/F5/TEST-VECTOR", &msg)
}

/// A synthetic 32-byte sighash message for a vector index.
pub fn message(index: u32) -> [u8; 32] {
    seeded(0x6d, index)
}
