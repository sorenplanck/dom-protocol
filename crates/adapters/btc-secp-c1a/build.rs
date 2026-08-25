// Build script of the C1a/C1b conformance harness.
//
// Compiles src/c1a_driver.c, which #includes the pinned upstream tests.c
// (and through it the whole library) from the vendored tree of
// btc-secp-sys. Same module set and precomputation parameters as the
// production build; VERIFY is defined because the upstream test suite is
// designed to run with its internal verification checks on — that adds
// assertions, it never changes semantics.

fn main() {
    let depend = "../btc-secp-sys/depend/secp256k1";
    let mut build = cc::Build::new();
    build
        .include(depend)
        .include(format!("{depend}/include"))
        .include(format!("{depend}/src"))
        // tests.c includes a Wycheproof data header that the -sys vendor
        // tarball does not ship; see vendor-extra/wycheproof/PROVENANCE.md.
        .include("vendor-extra")
        .flag_if_supported("-Wno-unused-function")
        .define("SECP256K1_BUILD", Some(""))
        .define("ENABLE_MODULE_MUSIG", Some("1"))
        .define("ENABLE_MODULE_SCHNORRSIG", Some("1"))
        .define("ENABLE_MODULE_EXTRAKEYS", Some("1"))
        .define("ECMULT_GEN_PREC_BITS", Some("4"))
        .define("ECMULT_WINDOW_SIZE", Some("15"))
        .define("VERIFY", Some("1"));

    if let Ok(target_endian) = std::env::var("CARGO_CFG_TARGET_ENDIAN") {
        if target_endian == "big" {
            build.define("WORDS_BIGENDIAN", Some("1"));
        }
    }

    build
        .file("src/c1a_driver.c")
        .file(format!("{depend}/src/precomputed_ecmult_gen.c"))
        .file(format!("{depend}/src/precomputed_ecmult.c"))
        .compile("libdominterop_c1a_harness.a");

    println!("cargo:rerun-if-changed=src/c1a_driver.c");
    println!("cargo:rerun-if-changed={depend}");
}
