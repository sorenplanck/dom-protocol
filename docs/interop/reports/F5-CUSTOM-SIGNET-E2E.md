# F5 Regtest and Custom-Signet Closure Evidence

```text
Date:             2026-08-12
Authority:        Foundation v0.18 (v0.17 closure incorporated); Annex M v3.3; D-027
Required nets:    regtest + custom Signet BIP-325
Public Signet:    optional; no gate, roadmap or release authority
Mainnet:          excluded
Execution state:  F5 COMPLETE; G-F5 PASS
```

## Frozen custom-Signet profile

The machine-readable authority is `infra/signet/network.json`. It pins
Bitcoin Core v31.0.0 and both official distribution hashes, the unmodified
official `contrib/signet/miner`, the fixed Signet genesis, message magic,
challenge and challenge hash. The challenge is a non-trivial P2PK/1-of-1
BIP-325 script. Its signer WIF is mode 0600 outside Git and is never copied
to evidence.

Miner/signer and observer run as different Bitcoin Core processes with
different datadirs, P2P ports and RPC ports. Every block is produced by the
official Signet miner. The committed conformance CSV is 17 blocks; production
remains 144. Evidence policy requires two linked successor headers.

## Closing execution

The final clean execution was `local-20260812-post-rebase`, tested at
`fcba7508f7c745d36185c6e98488f0ccac57882f`, tree
`dfe1c69db6bfca776b3b27cd5e5c029738172285`. It ran for 480,165 ms and
returned exit code 0. Its content-addressed evidence directory is
`artifacts/f5-custom-signet/local-20260812-post-rebase/`; `manifest.json` has
SHA-256
`39b8dd8ffe0029074a259ab09bd3e90705d1364d600be447aaa92fee3fb129eb`.
The manifest covers 82 files; all hashes and all 175 recorded zero exit codes
were independently recomputed. The complete secret-free set is published as
`docs/evidence/F5-2026-08-12/custom-signet-evidence.tar.gz`, archive SHA-256
`231a1b8701b5989dd4c81114cb462deb69e3cec21fa327fd079859ff6bab1291`.

The funding transaction is
`f11fbe7b5724a28dd703da24071e34c8b9e1bb6f74960c15457cd0e23743d571`
(wtxid `31d2b79f6705c01e991fdc76faf536e5a9cd4c429b6db6879bb05a13d96459bc`).
The four claim txids are:

- E01 `2bb9959618ac2216602e01560446e501b5970627ec2b11908d40edf5833f12d4`;
- E02 `b7aba65f8ea8b83eb5394a6dea2ea14474a6c15e07f989cb22f531995e5440eb`;
- E03 `f644bc24d72a28ccad8019658addbbff98f123bf0935e992273a97779e585329`;
- E04 `8349873a93835d3e14216b913c10c3d59e5c8d10104c2675d0ed01e6cd82a205`.

The refund txids are E05
`0468bd4e0a7fe2ca1735c0c74c610f002b9302f3d14d0d11324029d8021ab79f`
and E06
`4ba4d65648ff5fded516e483023bfc628b50a42e0ec74f7afa43e3b36fa52eed`.
Every receipt proves two linked successor headers, full-block Merkle root and
witness commitment, Keystone verification, durable observer idempotency,
`VerifiedBitcoinOutcomeV1` consumption by USPE and one economic terminal.
For E01-E04, BIP340 verification is true and the public extracted point equals
the committed adaptor point exactly (`t*G=T`); the scalar is never retained in
the evidence.

The final manifest also retains the public deterministic inputs and C1a seed,
the exact invocation contract, and explicit entropy boundaries. Private test
scalars, nonce seeds, wallet material and the challenge WIF remain excluded;
their source or runtime boundary is pinned without disclosing secret values.

| Scope | Required result | Current result |
|---|---|---|
| Regtest funding, claim, CSV=144 refund | Bitcoin Core acceptance and confirmation | PASS; exit 0; Core v31.0.0; 22,636 ms |
| Custom Signet E01-E16 | all rows fail-closed, idempotent and reconciled | PASS; 16/16; exit 0 |
| C1a/C1b/C2/C3/C4 | all cryptographic layers green | PASS |
| Workspace fmt/clippy/tests/docs/guards | exit 0 | PASS; full battery 1,553,219 ms; workspace tests 1,464,170 ms |
| Evidence and witness parser fuzzing | 10,000 runs per target | PASS; 20,000 total; pinned nightly |
| Governance/BIP-325/crypto/evidence/reproducibility audits | no open P0/P1; P2 adjudicated | PASS |

The regtest revalidation used the production CSV=144 profile. Funding txid was
`59e9945f3a06a3949efd6a1d2db669e6909c46546f7446732fe671338fa51545`,
claim txid was
`a287d5a5c259041e3c015c8bb0b89000d6c8c3395f6d7c0e9220bab7fc9b71e8`,
and refund txid was
`fa953ba53d3e350367dd01118a6759bb4bae76f4a139bb9b3d02e61f8dc7e39e`.
The published regtest archive is
`docs/evidence/F5-2026-08-12/regtest-evidence.tar.gz`, SHA-256
`0885994defac7e10ff0455f773480eb5d25b28636d1e2285cfeacc636008f09f`.

The full validation record is published as
`docs/evidence/F5-2026-08-12/validation-evidence.tar.gz`, SHA-256
`61b2aa1ae68eeb64a6b7cbe4077aa3352e7aa627edcdf0672eadea5d8b23953e`.
Its 46-file manifest has SHA-256
`7f52ce9f8e2d74de2dc1f27436839c70f48bf4da9f266091bf9e838ab8650813`.
It preserves both the initial incompatible-nightly failure and the complete
from-zero rerun with 19/19 commands at exit 0.

## Findings corrected before the closing run

- replaced the historical OP_TRUE/single-node harness with the official-Core
  non-trivial P2PK split topology;
- made the custom-Signet template identity explicit in the real adapter;
- selected CSV=17 because it is the shortest conformance value minimally
  encoded by the unchanged adapter primitive; production CSV=144 is intact;
- kept nonce vaults and party journals in the ephemeral runtime, outside the
  evidence manifest;
- made E07 invalidate funding, E08 invalidate claim and E09 invalidate refund;
- made E14 mutate an actual witness signature byte;
- bound custom challenge, challenge hash and message magic at the evidence
  verifier boundary;
- required Core rejection for competing terminals and conflicting funding.

Additional closing corrections found by the live battery were: deterministic
ordered suffix replay after reorg; explicit disabling of wallet rebroadcast;
an accepted-block/height check around the official miner; byte-correct frozen
Signet genesis binding; and proof of two full linked successor headers. Every
one made the harness stricter. No consensus, production CSV, DOM core/wire/
mempool/Wallet or dom-adaptor primitive was changed.

The completion audit additionally found that the two parser fuzz commands in
M.14.2 had no executable targets. Both real verifier entry points now have
bounded libFuzzer targets; zero-input transactions fail closed instead of
indexing a missing input. The initially selected 2025 nightly could not compile
the current SQLite dependency, so the failure was retained, the nightly was
pinned to `nightly-2026-06-30`, and the entire battery was rerun from zero.

## Mandatory declarations

```text
DOM_SIM_IS_REAL_DOM=false
DOM_SCRIPTLESS_TOUCHED=false
DOM_CORE_TOUCHED=false
DOM_CONTRACTS_TOUCHED=false
DOM_WALLET_TOUCHED=false
BITCOIN_CONSENSUS_TOUCHED=false
KEYSTONE_CUSTODIAL=false
MAINNET_USED=false
```

Every M.15.2 operand is GREEN in the recorded evidence. Therefore F5 is
COMPLETE and G-F5 is PASS. Public Signet did not participate in this result
and cannot alter it under D-027.
