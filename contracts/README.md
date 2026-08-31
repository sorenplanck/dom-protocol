# DOM EVM condition locks

This directory contains the two permissionless settlement locks used by the
DOM↔EVM adapter:

- `ConditionLockV2`: native EVM asset;
- `ConditionLockERC20V2`: exact-accounting ERC-20 assets.

They are deliberately not a router, oracle, proxy or route coordinator. Route
ordering, signing authority, finality and recovery belong to `dom-interopd` and
the durable route executor. The contracts only enforce custody, the committed
adaptor secret, the beneficiary and the refund deadline.

No production deployment is declared by this directory merely because the
contracts compile or pass locally. A deployment becomes eligible only after a
release record is generated from a finalized chain and its facts are reviewed
and signed into `deployment-registry`.

## Reproducible inputs

The compiler and settings are frozen in `foundry.toml`:

- Solidity `0.8.24` (`0.8.24+commit.e11b9ed9`);
- EVM Shanghai;
- optimizer enabled, 20,000 runs;
- `via_ir = false`;
- metadata bytecode hash `none`.

`dependencies.lock.json` pins exact Git revisions, package versions and a
BLAKE2b-256 digest over every dependency source actually present in the three
release compilation units. `lib/` is generated and ignored; populate it with:

```sh
./scripts/bootstrap_dependencies.sh
```

The bootstrap refuses to replace an existing dependency directory. A later
release gate validates the compiled-source digest, so an existing but modified
dependency fails closed.

Run the build/test gate:

```sh
./scripts/check_release.sh
```

It formats-checks Solidity, compiles the release units twice into isolated
directories, requires byte-identical artifacts, checks the dependency pins,
runs all Foundry tests and runs the release-manifest refusal tests.

## Deployment

`DeployScript` has no privileged constructor input and deploys both locks with
ordinary `CREATE`. There is no project-specific CREATE2 scheme. The release
manifest therefore rejects CREATE2 records instead of guessing a salt or
factory.

The signing key is supplied only through Foundry wallet flags. It is not an
environment variable consumed by the Solidity script. The target chain must be
declared independently:

```sh
EXPECTED_CHAIN_ID=11155111 forge script script/Deploy.s.sol:DeployScript \
  --rpc-url "$RPC_URL" \
  --broadcast \
  --ledger
```

Do not generate the release record until both deployment blocks are finalized.
Keep RPC credentials out of command arguments by placing a credential-free
local/sidecar endpoint in the named environment variable:

```sh
export DOM_EVM_RELEASE_RPC_URL=http://127.0.0.1:8545
python3 scripts/release_manifest.py build \
  --artifacts-dir out \
  --broadcast broadcast/Deploy.s.sol/11155111/run-latest.json \
  --expected-chain-id 11155111 \
  --output release/sepolia-11155111.json
```

Rebuild every fact and compare the public record byte-for-byte:

```sh
python3 scripts/release_manifest.py verify \
  --artifacts-dir out \
  --broadcast broadcast/Deploy.s.sol/11155111/run-latest.json \
  --expected-chain-id 11155111 \
  --manifest release/sepolia-11155111.json
```

The generated `registry_projection` contains the contract addresses/runtime
codehashes and the seven build/deployment fields that map directly to
`EvmDeploymentV1`. It sets `finalized_tag_required = true`, because both the
release verifier and the EVM adapter refuse to degrade that guarantee. It does
not choose the remaining runtime policy: `page_size`, gas limit and fee
ceilings remain explicit registry-authority decisions.

Release records contain no secret, endpoint or signer metadata. They are not a
substitute for the threshold-signed deployment registry.
