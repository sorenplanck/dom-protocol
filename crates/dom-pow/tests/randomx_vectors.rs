//! RandomX test vectors for cross-implementation validation.

use dom_pow::randomx_seed_height;

#[test]
fn vector_genesis_block() {
    let seed_height = randomx_seed_height(0);
    assert_eq!(seed_height, 0);
}

#[test]
fn vector_height_2048_first_rotation() {
    let seed_height = randomx_seed_height(2048);
    assert_eq!(seed_height, 1984);
}

#[test]
fn vector_height_4096_second_rotation() {
    let seed_height = randomx_seed_height(4096);
    assert_eq!(seed_height, 4032);
}
