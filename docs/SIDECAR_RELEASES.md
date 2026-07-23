# Managed sidecar releases

The wallet accepts a sidecar only when a signed `sidecar-manifest.json` and a
signature for the binary verify under one of the two keys compiled into the
wallet. SHA-256 is an additional integrity check; it does not authenticate a
release by itself.

`v0.1.2` deliberately has no manifest. It is therefore not eligible for
automatic promotion and remains a manual installation release.

## Producing the next release manifest

Build the release binary first. Then run the generator against that exact
binary; it calculates its own SHA-256 and emits its compiled version, git
revision, P2P/RPC protocol versions, storage-schema support, chain ID and
genesis hash. No identity field or artifact digest is entered by hand.

```bash
cargo build --release -p dom-node
export DOM_SIDECAR_ARTIFACT_PLATFORM=linux-x86_64
export DOM_MIN_WALLET_VERSION=0.3.1
export DOM_SIDECAR_PUBLISHED_AT=2026-07-23T00:00:00Z
bash scripts/generate-sidecar-manifest.sh mainnet \
  https://github.com/sorenplanck/dom-protocol/releases/download/vX.Y.Z/dom-node-linux-x86_64
minisign -Sm sidecar-manifest.json -s /secure/path/dom-release.key
minisign -Sm target/release/dom-node -s /secure/path/dom-release.key
```

Publish the manifest, `sidecar-manifest.json.minisig`, binary, and binary
`.minisig` together. The wallet refuses the release if any is absent or if the
candidate's chain ID, genesis, configured network, protocol versions, or
storage support disagrees with the current node.

## Probe mode

`dom-node --probe` binds authenticated RPC only on `127.0.0.1:0`, generates a
one-use process token, never opens `DOM_DATA_DIR`, does not start P2P, and does
not mine. It returns build metadata and exits after `/shutdown` or 30 seconds.
