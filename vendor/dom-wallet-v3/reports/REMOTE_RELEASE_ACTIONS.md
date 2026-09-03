# Remote release actions

Date: 2026-07-28

No remote feed, asset, tag, GitHub release, or signing key was modified during
this campaign. No private key was accessed. No push, tag, publication, release,
artifact upload, feed mutation, or remote deployment was attempted. Code
closure is separate from publication closure.

The local release gate is **PASS**. `scripts/verify-wallet-findings.sh`
completed with exit 0, including the explicit real C1 Mainnet acceptance test
and the full all-target workspace suite. Publication was outside this campaign
and was not attempted.

The product now exposes only the signed Wallet updater. The misleading
`check_node_now` command and node/peer feed status UI were removed. The
experimental managed-sidecar policy library remains explicitly experimental;
it is not represented as an active product update feed.

Before a future Wallet release, an authorized release operator must:

1. Re-run the complete local gate on the exact reviewed commit in release CI
   and archive its successful output.
2. Build the exact reviewed commit through the pinned release workflow.
3. Produce platform artifacts and `latest.json`.
4. Sign the manifest and artifacts using the established offline Minisign
   ceremony. Do not expose private key material to this workspace or logs.
5. Publish the Wallet release assets.
6. Verify HTTPS origin, redirect allowlist, decoded public key/key ID, manifest
   expiry, artifact length, SHA-256, Minisign signature, and updater check.
7. Record the published tag, immutable artifact hashes, and verification output.

If node-only or peer-manifest delivery is desired later, it requires a separate
approved implementation with signed manifests, compatibility/rollback policy,
production call sites, local HTTP integration tests, publication, and
post-publication verification. Do not revive the removed UI until all of those
conditions are met.
