//! Generate a deterministic RandomX hash for a fixed (seed, preimage) pair.
//!
//! Run with: `cargo run -p dom-pow --example print_randomx_vector`
//! Use the printed bytes to freeze a test vector in `tests/randomx_vectors.rs`.

use dom_pow::randomx_pool::randomx_hash;

fn main() {
    let seed = [0u8; 32];
    let preimage = b"DOM/randomx/v1/vector/genesis";
    let h = randomx_hash(&seed, preimage).expect("randomx hash");
    println!("seed       = {}", hex(&seed));
    println!("preimage   = {:?}", std::str::from_utf8(preimage).unwrap());
    println!("randomx_hash = {}", hex(&h));
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}
