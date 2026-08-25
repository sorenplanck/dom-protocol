# vendor-extra/wycheproof

`ecdsa_dominterop_secp_v0_10_0_sha256_bitcoin_test.h` is the upstream file
`src/wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.h` at the pinned
revision 6152622613fdf1c5af6f31f74c427c4e9ee120ce of
BlockstreamResearch/secp256k1-zkp (the file was NOT shipped in the
secp256k1-zkp-sys 0.10.1 vendor tarball, but tests.c includes it).

SHA-256 of the file as fetched (byte-identical, zero renames needed —
it contains only Wycheproof ECDSA test data, no library identifiers):

    6ab33cbf2f88ff448dcaa3cdec144578d46a34468fd2a07d4ebe0f511423485a

Only the FILE NAME differs, because the tree-wide symbol rename of the
vendor tarball also rewrote the include string inside tests.c.
