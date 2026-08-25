// Build script for the vendored, pinned secp256k1-zkp (Annex M v3.2).
//
// Derived from secp256k1-zkp-sys 0.10.1's CC0 build script, with three
// changes, each of them the point of this crate's existence:
//   1. ENABLE_MODULE_MUSIG / SCHNORRSIG / EXTRAKEYS are defined — the
//      published -sys never compiles the MuSig2 module, and MuSig2 with
//      adaptor support is exactly what the Bitcoin leg requires (M.1.2);
//   2. the symbols carry the project prefix `dominterop_secp_v0_10_0_`
//      (already rewritten in the vendored tree), so this library can
//      coexist with any other secp256k1 copy in the same binary;
//   3. the produced archive is named after this crate.
//
// The vendored tree is the pin. No network access, no submodule, no
// "master": the exact upstream revision is recorded in
// depend/secp256k1-HEAD-revision.txt and in VENDOR.md.

fn main() {
    let mut base_config = cc::Build::new();
    base_config
        .include("depend/secp256k1/")
        .include("depend/secp256k1/include")
        .include("depend/secp256k1/src")
        .flag_if_supported("-Wno-unused-function")
        .define("SECP256K1_BUILD", Some(""))
        // Modules required by Annex M (MuSig2 needs schnorrsig+extrakeys).
        .define("ENABLE_MODULE_MUSIG", Some("1"))
        .define("ENABLE_MODULE_SCHNORRSIG", Some("1"))
        .define("ENABLE_MODULE_EXTRAKEYS", Some("1"))
        .define("ECMULT_GEN_PREC_BITS", Some("4"))
        .define("ECMULT_WINDOW_SIZE", Some("15"))
        .define("USE_EXTERNAL_DEFAULT_CALLBACKS", Some("1"));

    if let Ok(target_endian) = std::env::var("CARGO_CFG_TARGET_ENDIAN") {
        if target_endian == "big" {
            base_config.define("WORDS_BIGENDIAN", Some("1"));
        }
    }

    base_config
        .file("depend/secp256k1/src/secp256k1.c")
        .file("depend/secp256k1/src/precomputed_ecmult_gen.c")
        .file("depend/secp256k1/src/precomputed_ecmult.c")
        .compile("libdominterop_secp.a");

    println!("cargo:rerun-if-changed=depend");
}
