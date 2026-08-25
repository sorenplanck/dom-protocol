# Vendored secp256k1-zkp — pin provenance (Annex M v3.2, M.17 step 1)

```text
Upstream C library:   BlockstreamResearch/secp256k1-zkp
Upstream revision:    6152622613fdf1c5af6f31f74c427c4e9ee120ce
                      (recorded by the vendor script in
                      depend/secp256k1-HEAD-revision.txt)
Vendor vehicle:       secp256k1-zkp-sys 0.10.1 (crates.io), whose
                      published tarball ships this exact tree with
                      symbols pre-renamed for link isolation
Local delta:          1. symbol prefix rewritten
                         rustsecp256k1zkp_v0_10_0_  →
                         dominterop_secp_v0_10_0_
                         (mechanical, tree-wide, no semantic change)
                      2. build.rs enables ENABLE_MODULE_MUSIG,
                         ENABLE_MODULE_SCHNORRSIG and
                         ENABLE_MODULE_EXTRAKEYS — the published -sys
                         never compiles MuSig2, which is the entire
                         reason this crate exists
Upstream license:     MIT (depend/secp256k1/COPYING, preserved)
Registered as:        decision D-013 of the Foundation Document
                      (RATIFICATION PENDING until the C1–C4 conformance
                      evidence exists, per Annex M M.16)
```

## Why not the published crates

- `secp256k1-zkp` / `secp256k1-zkp-sys` 0.10.x/0.11.x do not compile or
  bind the MuSig2 module at all.
- `rust-secp256k1-zkp` git master (checked 2026-08-10, HEAD `c21fd68`)
  still has no MuSig2 bindings.
- upstream `secp256k1` (bitcoin-core) merged MuSig2 without the adaptor
  API (`musig_adapt` / `musig_extract_adaptor` /
  `nonce_process(adaptor)`), which the Bitcoin leg requires (M.4).
- reimplementing BIP327/BIP340 in Rust is forbidden by Annex M M.0.4.

## Link isolation

The `real-dom-adaptor` builds already pull the PUBLISHED zkp-sys into
the build graph through `dom-crypto`. Two measures keep the copies from
ever colliding:

1. every C symbol carries the project prefix
   (`dominterop_secp_v0_10_0_*`), so both libraries can even coexist in
   one binary;
2. `links = "dominterop_secp_v0_10_0"` in Cargo.toml, so cargo itself
   rejects any second crate claiming this native library.

## Update protocol

The vendored tree is the pin. Updating it is an intentional decision
that supersedes D-013: re-vendor, re-prefix, re-run the full C1–C4
conformance battery, and record the new revision here and in the
Foundation Document. Never edit files under `depend/` by hand.
