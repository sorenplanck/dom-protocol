# DOM XMR live sidecar (GPL-3.0-only)

This crate is copied into the pinned `eigenwallet/core` checkout by
`scripts/build-sidecar.sh`. It uses Eigenwallet's `monero-wallet-ng` to:

1. verify the exact funding output with the private view key;
2. require the funding transaction to be mined and spendable;
3. reconstruct the combined spend key inside the process;
4. select the funding output, decoys and fee;
5. build/sign a CLSAG + Bulletproofs+ sweep;
6. atomically cache the exact signed raw transaction by Kaystra effect id.

It binds only to loopback and requires `DOM_XMR_SIDECAR_AUTH_HEX`.
The cache directory must reside on durable local storage.
