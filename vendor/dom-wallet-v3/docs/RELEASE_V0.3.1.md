# DOM Wallet V3 v0.3.1 release runbook

This runbook publishes the immutable `wallet-v0.3.1` release. It deliberately
keeps release signing keys out of GitHub Actions and publishes the updater feed
only after every file referenced by that feed is already attached to a draft
GitHub Release.

Do not reuse or move `wallet-v0.3.0`. That tag and Release are already public.

## 1. Operator variables and prerequisites

Run the networked commands from the repository root with Bash. Substitute the
absolute offline key path only on the offline signing station.

```bash
export REPO='sorenplanck/dom-wallet-v3'
export BRANCH='redesign/restore-remote-scan'
export VERSION='0.3.1'
export TAG='wallet-v0.3.1'
export MINISIGN_PUBLIC_KEY='RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3'
export RELEASE_WORKDIR
RELEASE_WORKDIR="$(mktemp -d /tmp/dom-wallet-v0.3.1.XXXXXX)"
export ACTIONS_DIR="$RELEASE_WORKDIR/actions"
export RELEASE_DIR="$RELEASE_WORKDIR/release"
mkdir -p "$ACTIONS_DIR" "$RELEASE_DIR"

gh auth status
git fetch origin --tags
test "$(git branch --show-current)" = "$BRANCH"
test -z "$(git status --porcelain)"
test -z "$(git ls-remote --tags origin "refs/tags/$TAG")"
```

Required local tools are `git`, `gh`, `cargo`, Node.js/npm, `jq`, GNU
`sha256sum`, `curl`, `minisign`, and a secure transfer mechanism for moving
public artifacts to and detached signatures from the offline signing station.
The Minisign secret key must never enter this repository, GitHub, GitHub
Actions, shell logs, or the networked release workspace.

## 2. Final release commit gates

The final commit must already contain:

- the final DOM Protocol crate pin and refreshed `Cargo.lock`;
- wallet version `0.3.1` in `Cargo.toml`, `frontend/package.json`,
  `frontend/package-lock.json`, `src-tauri/tauri.conf.json`, and the resolved
  workspace packages in `Cargo.lock`;
- the same embedded node revision and version in updater metadata;
- the critical legacy deterministic-coinbase regression fix;
- this runbook.

Set the node commit supplied by the DOM Protocol release operator, then verify
all identities before building:

```bash
export FINAL_NODE_COMMIT='<40-hex final DOM Protocol commit>'
export RELEASE_SHA
RELEASE_SHA="$(git rev-parse HEAD)"

test "${#FINAL_NODE_COMMIT}" -eq 40
printf '%s\n' "$FINAL_NODE_COMMIT" | grep -Eq '^[0-9a-f]{40}$'
test "$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' Cargo.toml)" = "$VERSION"
test "$(node -p 'require("./frontend/package.json").version')" = "$VERSION"
test "$(node -p 'require("./src-tauri/tauri.conf.json").version')" = "$VERSION"

export LOCKED_NODE_VERSION
LOCKED_NODE_VERSION="$(sed -n '/^name = "dom-node"$/,/^$/s/^version = "\([^"]*\)"$/\1/p' Cargo.lock)"
export LOCKED_NODE_REVISION
LOCKED_NODE_REVISION="$(sed -n '/^name = "dom-node"$/,/^$/s/^source = ".*#\([0-9a-f]\{40\}\)"$/\1/p' Cargo.lock)"
export REPORTED_NODE_VERSION
REPORTED_NODE_VERSION="$(sed -n 's/^const EMBEDDED_NODE_VERSION: &str = "\([^"]*\)";$/\1/p' crates/dom-wallet-updater/examples/feed_tool.rs)"
export REPORTED_NODE_REVISION
REPORTED_NODE_REVISION="$(sed -n 's/^pub const EMBEDDED_NODE_REVISION: &str = "\([0-9a-f]\{40\}\)";$/\1/p' crates/dom-wallet-updater/src/lib.rs)"

test "$LOCKED_NODE_REVISION" = "$FINAL_NODE_COMMIT"
test "$REPORTED_NODE_REVISION" = "$LOCKED_NODE_REVISION"
test "$REPORTED_NODE_VERSION" = "$LOCKED_NODE_VERSION"
test "$(git rev-parse HEAD)" = "$RELEASE_SHA"
test -z "$(git status --porcelain)"
```

Any failed comparison is a release blocker. In particular, do not generate a
feed whose `embedded_node_revision` or `embedded_node_version` differs from the
node resolved in `Cargo.lock`.

Run the permanent legacy-coinbase regression test and the complete locked
suite using the commands recorded by the final release test report. Commit all
source, version, pin, lockfile, metadata, test, and documentation changes before
continuing. Recompute `RELEASE_SHA` after that commit.

## 3. Push the branch and run the candidate matrix

A branch push does not trigger `release-wallet.yml`. Push the final commit,
then dispatch the three-platform candidate matrix explicitly:

```bash
git push origin HEAD:refs/heads/redesign/restore-remote-scan

gh workflow run release-wallet.yml \
  --repo "$REPO" \
  --ref "$BRANCH" \
  -f validation_only=false \
  -f release_version=0.3.1

export CANDIDATE_RUN_ID
for attempt in $(seq 1 30); do
  CANDIDATE_RUN_ID="$(
    gh run list \
      --repo "$REPO" \
      --workflow release-wallet.yml \
      --branch "$BRANCH" \
      --event workflow_dispatch \
      --limit 20 \
      --json databaseId,headSha \
      --jq ".[] | select(.headSha == \"$RELEASE_SHA\") | .databaseId" |
      head -n 1
  )"
  test -n "$CANDIDATE_RUN_ID" && break
  sleep 2
done
test -n "$CANDIDATE_RUN_ID"
gh run watch "$CANDIDATE_RUN_ID" --repo "$REPO" --exit-status
```

Confirm that `validate` and all Linux, Windows, and macOS package jobs are
green:

```bash
gh run view "$CANDIDATE_RUN_ID" \
  --repo "$REPO" \
  --json headSha,conclusion,jobs \
  --jq '{headSha,conclusion,jobs:[.jobs[]|{name,conclusion}]}'
```

Do not publish artifacts from this candidate run. It proves the branch, but the
release artifacts must come from the immutable tag run below.

## 4. Create and push the immutable tag

Only after the candidate matrix is green:

```bash
test "$(git rev-parse HEAD)" = "$RELEASE_SHA"
test -z "$(git status --porcelain)"
git tag -a "$TAG" "$RELEASE_SHA" -m "DOM Wallet V3 v0.3.1"
test "$(git rev-parse "$TAG^{commit}")" = "$RELEASE_SHA"
git push origin "refs/tags/$TAG"
```

The tag push automatically starts `release-wallet.yml` again. This second run
is authoritative because its artifacts are bound to the public immutable tag:

```bash
export TAG_RUN_ID
for attempt in $(seq 1 30); do
  TAG_RUN_ID="$(
    gh run list \
      --repo "$REPO" \
      --workflow release-wallet.yml \
      --branch "$TAG" \
      --event push \
      --limit 20 \
      --json databaseId,headSha \
      --jq ".[] | select(.headSha == \"$RELEASE_SHA\") | .databaseId" |
      head -n 1
  )"
  test -n "$TAG_RUN_ID" && break
  sleep 2
done
test -n "$TAG_RUN_ID"
gh run watch "$TAG_RUN_ID" --repo "$REPO" --exit-status
```

Verify the SHA and all jobs again:

```bash
gh run view "$TAG_RUN_ID" \
  --repo "$REPO" \
  --json headSha,conclusion,jobs \
  --jq '{headSha,conclusion,jobs:[.jobs[]|{name,conclusion}]}'
```

## 5. Download the tag-run Actions artifacts

The workflow does not create GitHub Release assets. It stores three Actions
artifacts, named with the release commit:

- `dom-wallet-linux-x86_64-$RELEASE_SHA`
- `dom-wallet-windows-x86_64-$RELEASE_SHA`
- `dom-wallet-macos-aarch64-$RELEASE_SHA`

Download them from the tag run:

```bash
gh run download "$TAG_RUN_ID" --repo "$REPO" --dir "$ACTIONS_DIR"

test -d "$ACTIONS_DIR/dom-wallet-linux-x86_64-$RELEASE_SHA"
test -d "$ACTIONS_DIR/dom-wallet-windows-x86_64-$RELEASE_SHA"
test -d "$ACTIONS_DIR/dom-wallet-macos-aarch64-$RELEASE_SHA"
```

The same files are available in the GitHub UI at:

```text
https://github.com/sorenplanck/dom-wallet-v3/actions/runs/<TAG_RUN_ID>
```

Open the run, scroll to **Artifacts**, and download all three archives if `gh`
is unavailable.

## 6. Verify CI checksums and stage release files

Each Actions artifact contains a platform-specific
`SHA256SUMS-<target>.txt`. Verify those manifests before copying anything:

```bash
while IFS= read -r -d '' checksum_file; do
  (
    cd "$(dirname "$checksum_file")"
    sha256sum --check "$(basename "$checksum_file")"
  )
done < <(find "$ACTIONS_DIR" -type f -name 'SHA256SUMS-*.txt' -print0)
```

Flatten the native bundles into the release staging directory. A duplicate
filename is a hard failure:

```bash
while IFS= read -r -d '' source_file; do
  destination="$RELEASE_DIR/$(basename "$source_file")"
  test ! -e "$destination"
  cp -p -- "$source_file" "$destination"
done < <(
  find "$ACTIONS_DIR" -type f \
    \( -name '*.AppImage' \
       -o -name '*.deb' \
       -o -name '*.rpm' \
       -o -name '*-setup.exe' \
       -o -name '*.msi' \
       -o -name '*.dmg' \
       -o -name '*.app.tar.gz' \) \
    -print0
)

# GitHub normalizes spaces in uploaded asset names. Normalize them ourselves
# before feed authoring so the signed URLs and the eventual asset names cannot
# diverge.
while IFS= read -r -d '' source_file; do
  normalized_name="${source_file##*/}"
  normalized_name="${normalized_name// /.}"
  destination="$RELEASE_DIR/$normalized_name"
  test ! -e "$destination"
  mv -- "$source_file" "$destination"
done < <(find "$RELEASE_DIR" -maxdepth 1 -type f -name '* *' -print0)

export APPIMAGE
APPIMAGE="$RELEASE_DIR/DOM.Wallet.V3_${VERSION}_amd64.AppImage"
export WINDOWS_UPDATER
WINDOWS_UPDATER="$RELEASE_DIR/DOM.Wallet.V3_${VERSION}_x64-setup.exe"
export MACOS_UPDATER
MACOS_UPDATER="$RELEASE_DIR/DOM.Wallet.V3.app.tar.gz"
test -f "$APPIMAGE"
test -f "$WINDOWS_UPDATER"
test -f "$MACOS_UPDATER"
```

Generate one deterministic checksum inventory for every staged native bundle,
then verify it immediately:

```bash
(
  cd "$RELEASE_DIR"
  find . -maxdepth 1 -type f \
    \( -name '*.AppImage' \
       -o -name '*.deb' \
       -o -name '*.rpm' \
       -o -name '*-setup.exe' \
       -o -name '*.msi' \
       -o -name '*.dmg' \
       -o -name '*.app.tar.gz' \) \
    -printf '%f\0' |
    sort -z |
    xargs -0 sha256sum
) > "$RELEASE_DIR/SHA256SUMS.txt"

(
  cd "$RELEASE_DIR"
  sha256sum --check SHA256SUMS.txt
)
```

## 7. Draft the feed, then sign offline

Generate the draft close to publication. Its `published_at` is the current UTC
time and its `expires_at` is exactly 30 days later:

```bash
cargo run --locked -p dom-wallet-updater --example feed_tool -- \
  draft "$RELEASE_DIR" "$VERSION" "$RELEASE_SHA"
```

Transfer these four files to the offline signing station:

1. the AppImage;
2. the Windows `-setup.exe`;
3. the macOS `.app.tar.gz`;
4. `SHA256SUMS.txt`.

On the offline station:

```bash
export RELEASE_DIR='/absolute/offline/path/to/staged-files'
export MINISIGN_SECRET_KEY='/absolute/offline/path/to/minisign.key'
export MINISIGN_PUBLIC_KEY='RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3'
export APPIMAGE
APPIMAGE="$(find "$RELEASE_DIR" -maxdepth 1 -type f -name '*_amd64.AppImage' -print -quit)"
export WINDOWS_UPDATER
WINDOWS_UPDATER="$(find "$RELEASE_DIR" -maxdepth 1 -type f -name '*-setup.exe' -print -quit)"
export MACOS_UPDATER
MACOS_UPDATER="$(find "$RELEASE_DIR" -maxdepth 1 -type f -name '*.app.tar.gz' -print -quit)"
test -n "$APPIMAGE"
test -n "$WINDOWS_UPDATER"
test -n "$MACOS_UPDATER"

minisign -Sm "$APPIMAGE" -s "$MINISIGN_SECRET_KEY"
minisign -Vm "$APPIMAGE" -x "$APPIMAGE.minisig" -P "$MINISIGN_PUBLIC_KEY"

minisign -Sm "$WINDOWS_UPDATER" -s "$MINISIGN_SECRET_KEY"
minisign -Vm "$WINDOWS_UPDATER" -x "$WINDOWS_UPDATER.minisig" -P "$MINISIGN_PUBLIC_KEY"

minisign -Sm "$MACOS_UPDATER" -s "$MINISIGN_SECRET_KEY"
minisign -Vm "$MACOS_UPDATER" -x "$MACOS_UPDATER.minisig" -P "$MINISIGN_PUBLIC_KEY"

minisign -Sm "$RELEASE_DIR/SHA256SUMS.txt" -s "$MINISIGN_SECRET_KEY"
minisign -Vm "$RELEASE_DIR/SHA256SUMS.txt" \
  -x "$RELEASE_DIR/SHA256SUMS.txt.minisig" \
  -P "$MINISIGN_PUBLIC_KEY"
```

Return only the four `.minisig` files to the matching paths in
`$RELEASE_DIR`. Verify them again on the networked staging machine:

```bash
minisign -Vm "$APPIMAGE" -x "$APPIMAGE.minisig" -P "$MINISIGN_PUBLIC_KEY"
minisign -Vm "$WINDOWS_UPDATER" -x "$WINDOWS_UPDATER.minisig" -P "$MINISIGN_PUBLIC_KEY"
minisign -Vm "$MACOS_UPDATER" -x "$MACOS_UPDATER.minisig" -P "$MINISIGN_PUBLIC_KEY"
minisign -Vm "$RELEASE_DIR/SHA256SUMS.txt" \
  -x "$RELEASE_DIR/SHA256SUMS.txt.minisig" \
  -P "$MINISIGN_PUBLIC_KEY"
```

The first finalize pass injects those three updater signatures and creates the
exact canonical manifest bytes:

```bash
cargo run --locked -p dom-wallet-updater --example feed_tool -- \
  finalize "$RELEASE_DIR"
test -f "$RELEASE_DIR/dom-manifest-canonical.bin"
test ! -f "$RELEASE_DIR/latest.json"
```

Transfer `dom-manifest-canonical.bin` to the offline station. Sign and verify it
there, then return only its detached signature:

```bash
minisign -Sm "$RELEASE_DIR/dom-manifest-canonical.bin" -s "$MINISIGN_SECRET_KEY"
minisign -Vm "$RELEASE_DIR/dom-manifest-canonical.bin" \
  -x "$RELEASE_DIR/dom-manifest-canonical.bin.minisig" \
  -P "$MINISIGN_PUBLIC_KEY"
```

Back on the networked staging machine, verify the returned signature and run
the second finalize pass:

```bash
minisign -Vm "$RELEASE_DIR/dom-manifest-canonical.bin" \
  -x "$RELEASE_DIR/dom-manifest-canonical.bin.minisig" \
  -P "$MINISIGN_PUBLIC_KEY"

cargo run --locked -p dom-wallet-updater --example feed_tool -- \
  finalize "$RELEASE_DIR"
cargo run --locked -p dom-wallet-updater --example feed_tool -- \
  verify "$RELEASE_DIR"
```

`latest.json` is not signed as a separate file. Its authenticated
`dom_manifest.manifest_signature` is the detached signature over
`dom-manifest-canonical.bin`, and it carries the three base64-encoded artifact
signatures.

Verify the final identity before uploading:

```bash
jq -e \
  --arg version "$VERSION" \
  --arg tag "$TAG" \
  --arg wallet_revision "$RELEASE_SHA" \
  --arg node_version "$LOCKED_NODE_VERSION" \
  --arg node_revision "$LOCKED_NODE_REVISION" \
  '
    .version == $version and
    .dom_manifest.version == $version and
    .dom_manifest.wallet_revision == $wallet_revision and
    .dom_manifest.embedded_node_version == $node_version and
    .dom_manifest.embedded_node_revision == $node_revision and
    .dom_manifest.channel == "stable" and
    .dom_manifest.draft == false and
    .dom_manifest.prerelease == false and
    all(.dom_manifest.artifacts[];
      (.url | contains("/releases/download/\($tag)/")))
  ' "$RELEASE_DIR/latest.json"
```

If publication is delayed materially after `draft`, discard
`latest.draft.json`, `dom-manifest-canonical.bin`,
`dom-manifest-canonical.bin.minisig`, and `latest.json`, rerun `draft`, and
repeat the canonical-manifest signing steps. The three artifact signatures do
not change as long as the artifact bytes do not change.

## 8. Create a draft GitHub Release

Prepare reviewed release notes outside `$RELEASE_DIR`. The two external
regressions covered by this release should be described as fixes, not as known
open issues:

- wallet synchronization keeps following the canonical tip and retries
  transient `Core is not ready`;
- mining waits through transient synchronization gaps and resumes without a
  stop/start cycle.

Create a draft Release. A draft cannot replace the current
`releases/latest/download/` endpoint:

```bash
export RELEASE_NOTES="$RELEASE_WORKDIR/RELEASE_NOTES.md"
test -s "$RELEASE_NOTES"

gh release create "$TAG" \
  --repo "$REPO" \
  --verify-tag \
  --draft \
  --title "DOM Wallet V3 v0.3.1" \
  --notes-file "$RELEASE_NOTES"
```

Upload every staged file except the draft feed and `latest.json`:

```bash
mapfile -d '' RELEASE_ASSETS < <(
  find "$RELEASE_DIR" -maxdepth 1 -type f \
    ! -name 'latest.draft.json' \
    ! -name 'latest.json' \
    -print0
)
test "${#RELEASE_ASSETS[@]}" -gt 0
gh release upload "$TAG" --repo "$REPO" "${RELEASE_ASSETS[@]}"
```

Confirm the draft still exists and inspect the complete asset inventory:

```bash
gh release view "$TAG" \
  --repo "$REPO" \
  --json isDraft,isPrerelease,assets \
  --jq '{isDraft,isPrerelease,assets:[.assets[].name]}'
```

Do not continue unless every URL referenced by `latest.json` has a matching
artifact name in that inventory, and the artifact, checksum, and canonical
manifest signatures are present.

## 9. Upload `latest.json` last, then publish

Upload the feed only after all referenced artifacts already exist in the draft
Release:

```bash
gh release upload "$TAG" \
  --repo "$REPO" \
  "$RELEASE_DIR/latest.json"

gh release view "$TAG" \
  --repo "$REPO" \
  --json isDraft,assets \
  --jq '{isDraft,assets:[.assets[].name]}'
```

This ordering is mandatory. Installed v0.2.8 wallets resolve
`https://github.com/sorenplanck/dom-wallet-v3/releases/latest/download/latest.json`.
If a newly published latest feed points at artifacts that have not been
uploaded yet, those clients accept the signed update metadata and then fail to
download the selected artifact. Publishing a latest Release without
`latest.json` also makes the stable feed endpoint return 404. Keeping the
Release as a draft until all assets and the feed are present avoids both
partial-publication windows.

Publish the complete draft as the latest stable Release:

```bash
gh release edit "$TAG" \
  --repo "$REPO" \
  --draft=false \
  --prerelease=false \
  --latest
```

## 10. Post-publication verification

Download the public feed, compare it byte-for-byte with the signed local feed,
and require every referenced artifact URL to resolve:

```bash
curl --fail --location --silent --show-error \
  --output "$RELEASE_WORKDIR/latest.public.json" \
  'https://github.com/sorenplanck/dom-wallet-v3/releases/latest/download/latest.json'

cmp "$RELEASE_DIR/latest.json" "$RELEASE_WORKDIR/latest.public.json"

jq -r '.dom_manifest.artifacts[].url' "$RELEASE_DIR/latest.json" |
while IFS= read -r artifact_url; do
  curl --fail --location --silent --show-error --head "$artifact_url" >/dev/null
done

gh release view "$TAG" \
  --repo "$REPO" \
  --json isDraft,isPrerelease,tagName,url,assets
```

Record the `expires_at` value and schedule a feed refresh before it:

```bash
jq -r '.dom_manifest | {published_at,expires_at}' "$RELEASE_DIR/latest.json"
```

The feed fails closed after expiry. If no newer wallet release exists before
that date, re-author the feed with a fresh time window, re-sign the canonical
manifest, verify it, and replace the canonical manifest, its signature, and
`latest.json` using the same dependency-safe order.
